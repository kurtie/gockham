// Package gockham provides a framework for developing GO applications
// on lambda AWS
package gockham

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/kurtie/gockham/tools"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/golang-jwt/jwt"
)

// DeferredLogger captures logs and in the end generates a JSON
type DeferredLogger struct {
	startTime int64
	values    map[string]interface{}
	body      *bytes.Buffer
}

// Write writes something to the log. If it is not a string, a JSON version
// will be written if possible.
func (dl DeferredLogger) Write(msg interface{}) {
	switch v := msg.(type) {
	case string:
		dl.body.Write([]byte(v))
	case []byte:
		dl.body.Write(v)
	default:
		str, err := json.Marshal(v)
		if err != nil {
			dl.Write("value not writable")
		} else {
			dl.body.Write(str)
		}
	}
	dl.body.Write([]byte("\n"))
}

// AddValue adds a key-value pair to the current log
func (dl DeferredLogger) AddValue(key string, value interface{}) {
	dl.values[key] = value
}

// NewLogger creates a new deferred logger
func NewLogger() DeferredLogger {
	buf := make([]byte, 0, 2048)
	return DeferredLogger{
		startTime: time.Now().UnixNano() / 1000000,
		values:    map[string]interface{}{"app": App.Name},
		body:      bytes.NewBuffer(buf),
	}
}

// GetEntry gets the log entry
func (dl DeferredLogger) GetEntry() string {
	if OnLambda {
		return dl.GetJsonEntry()
	}
	return fmt.Sprintf("%v from %v (%v), %v bytes. %v", dl.values["req"], dl.values["ip"], dl.values["status"], dl.values["length"], dl.body.String())
}

func (dl DeferredLogger) GetJsonEntry() string {
	dl.values["time"] = time.Now().UnixNano()/1000000 - dl.startTime
	dl.values["content"] = dl.body.String()
	dl.values["reqId"] = fmt.Sprintf("%X-%d", App.StartTime, App.ServedRequests)
	j, _ := json.Marshal(dl.values)
	return string(j)
}

func (dl DeferredLogger) GetValue(key string) interface{} {
	return dl.values[key]
}

// Application represents a Gockham application
type Application struct {
	initError        error
	CipherKey        []byte                          // The key used for sign URLs and authentication token
	Crypt            Crypt                           // Struct with some cryptographic goodies
	StartTime        int64                           // When the application started
	ServedRequests   int                             // How many requests has been served
	ReceivedTriggers int                             // How many triggers han ben received
	Name             string                          // Application name
	Router           Router                          // The Router
	OnBegin          func() error                    // This code is executed when application is started
	OnBeginReq       func() error                    // This codes is executed before an action is executed unless it defines its own OnBegin
	OnEndReq         func(*Response)                 // This codes is executed after an action is executed unless it defines its own OnEnd
	OnEnd            func()                          // This code is only executed when served by governor on term signal
	OnError          func(interface{})               // This code is executed when an error is thrown dispatching a Request
	QueueEvent       func([]events.SQSMessage) error // This code is executed when a SQS trigger is received
}

// CompositeLambdaEvent contains all the possible lambda events that can be
// unmarshalled from lambda event
type CompositeLambdaEvent struct {
	events.APIGatewayProxyRequest
	events.SQSEvent
}

// Start initializes a Gockham application
func (app Application) Start() {
	sqs := false
	if len(os.Args) > 1 {
		switch os.Args[1] {
		/*
			case "gentplts":
				if len(os.Args) > 2 {
					generateTplts(os.Args[2])
				} else {
					generateTplts("prod")
				}
				return
		*/
		case "sqs":
			sqs = true
		default:
			fmt.Println("Wrong argument. Try gentplts")
			return
		}
	}

	Log := NewLogger()
	Log.AddValue("init", true)
	Log.Write("Intializing Gockham runtime v1.0.0")

	err := app.OnBegin()
	if err != nil {
		app.initError = err
		Log.Write("initialization error: " + err.Error())
	}

	if sqs {
		var event CompositeLambdaEvent
		event.Records = []events.SQSMessage{
			events.SQSMessage{
				Body: os.Args[2],
			},
		}
		_, err := app.handler(event)
		if err != nil {
			fmt.Println("Error: " + err.Error())
		}
	} else {
		// If not on lambda, catch interrupt signals and
		// call app.End
		if !OnLambda {
			//			os.Setenv("_LAMBDA_SERVER_PORT", "8001")
			//			go startServer()
			intSig := make(chan os.Signal, 1)
			signal.Notify(intSig, syscall.SIGINT)
			go func() {
				<-intSig
				app.OnEnd()
			}()
		}
		fmt.Println(Log.GetEntry())

		if HttpPort == "" {
			lambda.Start(app.handler)
		} else {
			initHttp(app)
		}
	}
}

// func (app Application) handler(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
func (app Application) handler(request CompositeLambdaEvent) (events.APIGatewayProxyResponse, error) {
	// If resource is empty then it should be a SQS trigger
	if request.Resource == "" {
		Request = RequestType{
			Log:   NewLogger(),
			Event: &request,
		}
		log := Request.Log

		app.ReceivedTriggers++
		log.AddValue("trigger", "sqs")
		if app.QueueEvent != nil {
			err := app.QueueEvent(request.Records)
			fmt.Println(log.GetEntry())
			return events.APIGatewayProxyResponse{}, err
		}
		return events.APIGatewayProxyResponse{}, errors.New("No QueueEvent function defined")
	}

	// Otherwise it has to be a GW Proxy Request event
	Request = newRequest(&request)
	log := Request.Log
	App.ServedRequests++

	log.AddValue("req", request.HTTPMethod+":"+request.Path)
	log.AddValue("ip", Request.GetSourceIP())
	log.AddValue("agent", request.Headers["User-Agent"])
	if app.initError != nil {
		return events.APIGatewayProxyResponse{
			Body:       "Init error: " + app.initError.Error(),
			StatusCode: 500,
		}, nil
	}

	if !OnLambda && request.IsBase64Encoded {
		var err error
		Request.BinBody, err = base64.StdEncoding.DecodeString(Request.Event.Body)
		if err != nil {
			log.Write("Warning!: Request body could not be decoded!")
		}
	}

	resp := app.dispatchRequest()

	if resp == nil {
		errResp := ErrorResponse(500, "Gockham error!")
		resp = &errResp
	}
	// Intialize correctly response if it is empty, avoiding panicking
	if resp.Headers == nil {
		emptyResp := GenericResponse("", "text/plain")
		resp = &emptyResp
	}
	fmt.Println(log.GetEntry())

	// We dont want API calls to be cached
	resp.Headers["Expires"] = "0"
	if Request.Auth.Token != "" {
		resp.Headers["Authorization"] = Request.Auth.Token
	}

	if EnableCors {
		resp.Headers["X-Requested-With"] = "*"
		if resp.Headers["Access-Control-Allow-Headers"] == "" {
			resp.Headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
		}
		resp.Headers["Access-Control-Allow-Origin"] = "*"
		resp.Headers["Access-Control-Allow-Methods"] = "POST,GET,PUT,DELETE,QUERY,OPTIONS"
		if resp.Headers["Access-Control-Expose-Headers"] == "" {
			resp.Headers["Access-Control-Expose-Headers"] = "x-amzn-remapped-authorization,authorization"
		}
	}
	// Convert cookies array to Set-Cookie Headers
	resp.addCookieHeaders()
	// fmt.Printf("CORS %v, headers: %v\n", EnableCors, resp.Headers)
	return events.APIGatewayProxyResponse{
		Headers:         resp.Headers,
		Body:            resp.Body,
		StatusCode:      resp.Status,
		IsBase64Encoded: resp.IsBase64Encoded,
	}, nil
}

/*
// Process the stack trace: split into lines
let stack= m.Payload[key].split("\n")
// look for the line responsible for the panic
let idx= 0
while (stack[idx++].indexOf("panic.go")==-1 && idx < stack.length );
let trace= ""

	for (;idx<stack.length-1;idx+=2) {
		trace += stack[idx].split("(")[0]+ " -> " + stack[idx+1].split(" ")[0] + "<br>"
	}

payload += `<div class="entry trace"><b>${key}</b>: ${trace}</div>`
*/
func (app Application) GetStackTrace() []string {
	stack := string(debug.Stack())

	defer func() {
		r := recover()
		if r != nil {
			fmt.Println("GetStackTrace error!!!")
			debug.PrintStack()
			fmt.Println("Original error:")
			fmt.Println(stack)
		}
	}()

	lines := strings.Split(stack, "\n")
	idx := 0
	for ; idx < len(lines) && !strings.Contains(lines[idx], "panic.go"); idx++ {
	}
	// IF "panic.go" not found, then consider all the lines
	if idx >= len(lines) {
		idx = 0
	}
	idx2 := idx + 1
	for ; !strings.Contains(lines[idx2], "Application.handler") && idx2 < len(lines); idx2++ {
	}
	trace := make([]string, (idx2-idx-1)/2)
	for i := 0; i < len(trace); i++ {
		i2 := idx + i*2 + 1
		call := strings.Split(lines[i2], "(")[0]
		source := strings.Replace(strings.Split(lines[i2+1], " ")[0], "\t", "", 1)
		trace[i] = call + " -> " + source
	}
	return trace
}

func (app Application) dispatchRequest() *Response {
	defer func() {
		r := recover()
		if r != nil {
			// debug.PrintStack()
			trace := app.GetStackTrace()
			fmt.Printf("%v\n\t%v", r, strings.Join(trace, "\n\t"))
			defer func() {
				r := recover()
				if r != nil {
					fmt.Println("WARNING: OnError is panicking!")
					fmt.Println(r)
				}
			}()
			// Custom on error function
			app.OnError(r)
		}
	}()
	resp := app.Router.Dispatch()
	/*
		if resp.Status == 500 {
			// Limit the size of the error message
			idx := int(math.Min(255, float64(len(resp.Body))))
			msg := resp.Body[0:idx]
			app.OnError(msg)
		}
	*/
	return &resp
}

// ParseToken parses a JWT token and verifies it against Application.CipherKey
func (app Application) ParseToken(token string) (*jwt.Token, error) {
	return tools.ParseToken(token, app.CipherKey)
}

// GetURLSignature generates a JWT token that is valid for accessing to a
// signed URL for ttl seconds. Extra claims can be provided in the signature.
// The signature should be included in the URL as the query string parameter 'signature'.
func (app Application) GetURLSignature(url string, ttl int, claims jwt.MapClaims) string {
	token, err := tools.GetURLSignature(url, app.CipherKey, ttl, claims)
	if err != nil {
		Request.Log.Write("GetURLSignature: " + err.Error())
	}
	return token
}

// NewApp creates a new Gockham application
func NewApp(name string, key []byte) Application {
	t := time.Now().Unix()
	crypt, err := newCrypt()
	return Application{
		initError:  err,
		StartTime:  t,
		Crypt:      crypt,
		CipherKey:  key,
		Name:       name,
		Router:     NewRouter(),
		OnBegin:    func() error { return nil },
		OnBeginReq: func() error { return nil },
		OnEndReq:   func(*Response) {},
		OnEnd:      func() {},
		OnError:    func(interface{}) {},
	}
}

// Request is the current request being served
var Request RequestType

// App is the current application
var App Application

// OnLambda tells if the application is executing in the AWS Lambda environment or locally
var OnLambda = os.Getenv("AWS_EXECUTION_ENV") != ""

// EnableCors tells if CORS headers are to be added to Responses. Its true when the
// environment variable ENABLE_CORS takes the value true
var EnableCors = os.Getenv("ENABLE_CORS") == "true"

var Debug = os.Getenv("DEBUG") == "true"

// If HTTP port is present then lambda is not used
var HttpPort = os.Getenv("HTTP_PORT")

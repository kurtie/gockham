package gockham

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/aws/aws-lambda-go/events"
)

func initHttp(app Application) {
	fmt.Println("HttpPort", HttpPort)

	killSig := make(chan os.Signal, 1)
	signal.Notify(killSig, syscall.SIGINT, syscall.SIGTERM)
	signal.Notify(killSig, syscall.SIGINT, syscall.SIGKILL)
	go func() {
		<-killSig
		fmt.Println("Killing server")
		os.Exit(0)
	}()

	http.HandleFunc("/api/", app.httpHandler)
	if err := http.ListenAndServe(fmt.Sprint(":", HttpPort), nil); err != nil {
		fmt.Println("Error: " + err.Error())
		os.Exit(1)
	}
}

var ch = make(chan bool, 1)

// Get Goroutine id
/*
func getGID() string {
	now := time.Now()
	fmt.Println("start", now)
	var n string
	for i := 0; i < 100000; i = i + 1 {
		b := make([]byte, 64)
		b = b[:runtime.Stack(b, false)]
		b = /* b[10:bytes.LastIndexByte(b, ' ')] * / bytes.TrimPrefix(b, []byte("goroutine "))
		b = b[:bytes.IndexByte(b, ' ')]
		n = string(b)
	}
	fmt.Println("end", time.Now().Sub(now))
	return n
}
*/
func (app Application) httpHandler(w http.ResponseWriter, r *http.Request) {
	params0 := r.URL.Query()
	params := map[string]string{}
	for k, v := range params0 {
		params[k] = v[0]
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error reading body: %v", err)
		http.Error(w, "can't read body", http.StatusBadRequest)
		return
	}

	headers := map[string]string{}
	for k, v := range r.Header {
		headers[k] = v[0]
	}

	// Get IP. Check X-Forwarded-For header
	ip := headers["X-Forwarded-For"]
	if ip == "" {
		ip, _, _ = net.SplitHostPort(r.RemoteAddr)
	}
	contentType := headers["Content-Type"]
	isBase64Encoded := !(contentType == "" || strings.HasPrefix(contentType, "application/json") ||
		strings.HasPrefix(contentType, "application/xml") || strings.HasPrefix(contentType, "text/"))

	if isBase64Encoded {
		body = []byte(base64.StdEncoding.EncodeToString([]byte(body)))
	}

	var path = r.URL.Path // r.URL.EscapedPath()

	request := CompositeLambdaEvent{
		events.APIGatewayProxyRequest{
			Resource: "/{proxy+}",
			Path:     path,
			PathParameters: map[string]string{
				"proxy": path[5:], // avoid "/api/""
			},
			HTTPMethod:            r.Method,
			Headers:               headers,
			QueryStringParameters: params,
			Body:                  string(body),
			RequestContext: events.APIGatewayProxyRequestContext{
				Identity: events.APIGatewayRequestIdentity{
					SourceIP: ip,
				},
			},
		},
		events.SQSEvent{},
	}

	// Use a channel to serialize requests
	// This code is dangerous... if a request does not end server would block
	ch <- true
	resp, err := app.handler(request)
	<-ch

	if err != nil {
		resp = events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       "Gockham error: " + err.Error(),
			Headers: map[string]string{
				"Content-Type": "text/plain",
			},
		}
	}

	for k, v := range resp.Headers {
		w.Header().Set(k, v)
	}
	w.WriteHeader(resp.StatusCode)
	if resp.IsBase64Encoded {
		body, err := base64.StdEncoding.DecodeString(resp.Body)
		if err == nil {
			w.Write(body)
		} else {
			w.Write([]byte("Error in decode64 lambda output: " + err.Error()))
		}
	} else {
		w.Write([]byte(resp.Body))
	}
}

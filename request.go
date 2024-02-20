package gockham

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
)

// AuthInfo represents the request authentication information
type AuthInfo struct {
	Claims  jwt.MapClaims // Authentication claims
	Token   string        // JWT authentication token
	Subject string        // Authenticated user name
	User    any           // Authenticated user
}

// RequestType represents a Request
type RequestType struct {
	Log     DeferredLogger        // Logger for this request
	Event   *CompositeLambdaEvent // Lambda event for this request
	Auth    AuthInfo              // Authentication info got in "Authentication" HTTP header
	Signed  jwt.MapClaims         // Claims in URL signature got in "signature" query string parameter
	Lang    string                // Language for this request from "lang" path info parameter
	BinBody []byte                // Request body as bytes (always empty if on lambda)

	Action Action // Action that matched path
	vars   []any  // URL vars values
}

func (r RequestType) GetURLValue(name string) any {
	for i, n := range r.Action.varNames {
		if n == name {
			return r.vars[i]
		}
	}
	return nil
}

// GetSourceIP gets the request source IP
func (r RequestType) GetSourceIP() string {
	if r.Event == nil {
		return ""
	}
	return r.Event.RequestContext.Identity.SourceIP
}

// ExtractFormParamsFromBody extracts params from request body. Params
// are expected to be URL encoded in the form param1=value1& ... &paramN=valueN
func (r RequestType) ExtractFormParamsFromBody() map[string]string {
	body := r.Event.Body
	if r.Event.IsBase64Encoded {
		b, err := Decode64(body)
		if err == nil {
			body = string(b)
		} else {
			Request.Log.Write("Could not get parameters from invalid encoded body")
		}
	}

	params := strings.Split(body, "&")
	ret := map[string]string{}
	for _, p := range params {
		idx := strings.Index(p, "=")
		if idx >= 0 {
			val, err := url.QueryUnescape(p[idx+1:])
			if err == nil {
				ret[p[0:idx]] = val
			} else {
				Request.Log.Write("Invalid body URL parameter " + p)
			}
		}
	}
	return ret
}

/*
 * Request.Event.Body is a String so this does not work with binary files unless base64 encoding is used
 *
func (r RequestType) ProcessMultipart() (map[string][]string, map[string][]*multipart.FileHeader, error) {
	mediaType, params, err := mime.ParseMediaType(Request.Event.Headers["Content-Type"])
	if err == nil {
		if strings.HasPrefix(mediaType, "multipart/") {
			reader := strings.NewReader(Request.Event.Body)
			mr := multipart.NewReader(reader, params["boundary"])
			// This is max size allowed in memory
			form, err := mr.ReadForm(10000000)
			if err != nil {
				r.Log.Write("Error parsing multipart: " + err.Error())
			}
			return form.Value, form.File, nil
		}
	}

	return nil, nil, err
}
*/

func (r RequestType) UnmarshallBody() (map[string]any, error) {
	var ret map[string]any
	err := json.Unmarshal([]byte(Request.Event.Body), &ret)
	return ret, err
}

func (r RequestType) UnmarshallBodyAsStruct(obj any) error {
	return json.Unmarshal([]byte(Request.Event.Body), &obj)
}

/*
 * Gets form-encoded parameters at request body to a interface
 */
func (r RequestType) GetFormParamsAsStruct(obj any) error {
	params := r.ExtractFormParamsFromBody()
	val := reflect.ValueOf(obj).Elem()

	for i := 0; i < val.NumField(); i++ {
		valueField := val.Field(i)
		typeField := val.Type().Field(i)
		tag := typeField.Tag
		paramName := strings.ToLower(typeField.Name)
		tagValue := tag.Get("gck")
		required := false
		if tagValue != "" {
			for _, e := range strings.Split(tagValue, ";") {
				if e == "required" {
					required = true
				} else if strings.HasPrefix(e, "name:") {
					paramName = e[5:]
				} else {
					return errors.New(fmt.Sprintf("Unsupported tag %s in param %s", e, paramName))
				}
			}
		}
		reqValue := params[paramName]

		if valueField.CanSet() {
			if valueField.Kind() == reflect.Int {
				val, err := strconv.Atoi(reqValue)
				if err == nil && val != 0 {
					valueField.SetInt(int64(val))
				} else if required {
					return fmt.Errorf("Parameter %s had unparseable int value %s", paramName, reqValue)
				}
			} else if valueField.Kind() == reflect.String {
				if reqValue == "" {
					if required {
						return fmt.Errorf("Parameter %s cannot be empty", paramName)
					}
				} else {
					valueField.SetString(reqValue)
				}
			} else if valueField.Kind() == reflect.Bool {
				valueField.SetBool(reqValue == "1" || reqValue == "true")
			} else if valueField.Kind() == reflect.Float64 {
				val, err := strconv.ParseFloat(reqValue, 64)
				if err == nil && val != 0 {
					valueField.SetFloat(val)
				} else if required {
					return fmt.Errorf("Parameter %s had unparseable int value %s", paramName, reqValue)
				}
			} else if valueField.Kind() == reflect.Int64 {
				val, err := strconv.ParseInt(reqValue, 10, 64)
				if err == nil && val != 0 {
					valueField.SetInt(val)
				} else if required {
					return fmt.Errorf("Parameter %s had unparseable int value %s", paramName, reqValue)
				}
			} else if required {
				return fmt.Errorf("Parameter %s had unsupported type %s", paramName, valueField.Type())
			}
		}
	}
	return nil
}

func newRequest(event *CompositeLambdaEvent) RequestType {
	return RequestType{
		Log:   NewLogger(),
		Event: event,
		Auth:  CheckAuthToken(event.Headers["Authorization"]),
	}
}

// CheckAuthToken checks the validity of an authentication token
func CheckAuthToken(tokenString string) AuthInfo {
	if len(tokenString) == 0 {
		return AuthInfo{}
	}
	if len(tokenString) > 7 && strings.ToLower(tokenString[:7]) == "bearer " {
		tokenString = tokenString[7:]
	}

	token, err := App.ParseToken(tokenString)
	if err != nil {
		if Debug {
			fmt.Println("Error parsing token (" + tokenString + ") at CheckAuthToken: " + err.Error())
		}
		return AuthInfo{}
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		remaining := int64(claims["exp"].(float64)) - time.Now().Unix()
		// If token is going to expire in 10 minutes, renew it

		if remaining < 600 {
			return GetAuthenticationToken(claims, 1800)
		}
		return AuthInfo{
			Claims:  claims,
			Subject: claims["sub"].(string),
		}
	}
	if Debug {
		fmt.Println("CheckAuthToken: Token invalid: " + tokenString)
	}
	return AuthInfo{}
}

// Login authenticates a user for ttl seconds by sending a JWT token  on
// the HTTP header Authorization. The authorization token contains the user
// name in the sub field, and the time to live in the exp field.
func Login(user string, ttl uint) {
	Request.Log.Write("User " + user + " has logged on")
	Request.Auth = GetAuthenticationToken(jwt.MapClaims{"sub": user}, ttl)
}

// GetAuthenticationToken creates the authentication info for given
// claims with a ttl seconds of validity. Provided claims must include
// in the "sub" field the name of authenticated user.
func GetAuthenticationToken(claims jwt.MapClaims, ttl uint) AuthInfo {
	// user := claims["sub"].(string)
	t := time.Now().Unix()
	if claims["nbf"] == nil {
		claims["nbf"] = t
	}
	claims["exp"] = t + int64(ttl)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(App.CipherKey)
	if err != nil {
		Request.Log.Write("Grant auth token: " + err.Error())
	}
	return AuthInfo{
		Subject: claims["sub"].(string),
		Claims:  claims,
		Token:   tokenString,
	}
}

// RenderPdf does a XSL transformation and returns a BASE64 encoded string
// with the representation of a PDF. The XSLT is done by invoking another
// Lambda function that uses FOP for that.
// xslUrl is a URL that contains the XSL
// xml is a string with the XML data
// config is a URL that contains the XML with the FOP configuration
/*
func RenderPdf(xslURL string, xml string, config string) (string, error) {
	xsl, err := tools.ReadURL(xslURL)
	if err == nil {
		pdf, err := tools.XslTransform(xsl, xml, config)

		if err == nil {
			return Encode64(pdf), nil
		}
	}
	return "", err
}
*/
// Response is the answer to a request
type Response struct {
	Status          int               // HTTP status code
	Headers         map[string]string // HTTP headers to be returned
	Body            string            // Response body
	IsBase64Encoded bool              // If response body is BASE64 encoded
	Cookies         []http.Cookie     // Cookies to be added to response
}

// AddCookie adds a cookie to the response
func (r *Response) AddCookie(c http.Cookie) {
	if len(r.Cookies) >= 5 {
		Request.Log.Write("WARNING! Only 5 cookies are supported per request")
	} else {
		r.Cookies = append(r.Cookies, c)
	}
}

// Ugly kludge for allowing several cookies on Lambda response.
var setCookieHeaderNames = []string{
	"set-cookie",
	"Set-cookie",
	"set-Cookie",
	"Set-Cookie",
	"SET-COOKIE",
}

func (r *Response) addCookieHeaders() {
	for i, c := range r.Cookies {
		r.Headers[setCookieHeaderNames[i]] = c.String()
	}
}

// GenericResponse creates a generic response of any given Content-Type
func GenericResponse(body string, contentType string) Response {
	return Response{
		Status:  200,
		Headers: map[string]string{"Content-Type": contentType},
		Body:    body,
	}
}

func DelayedResponse(r Response, ms int) Response {
	r.Headers["Delay"] = strconv.Itoa(ms)
	return r
}

func BinaryResponse(body []byte, contentType string) Response {
	return Response{
		Status:          200,
		Headers:         map[string]string{"Content-Type": contentType},
		Body:            Encode64(body),
		IsBase64Encoded: true,
	}
}

// JSONResponse creates a json response. The given object will be marshalled
// an its JSON representation will be sent as the response's body
func JSONResponse(i any) Response {
	var j string
	switch v := i.(type) {
	case string:
		j = v
	default:
		buf := new(bytes.Buffer)
		enc := json.NewEncoder(buf)
		// Avoid escaping HTML characters in JSON
		enc.SetEscapeHTML(false)
		if Debug && !OnLambda {
			enc.SetIndent("", "    ")
		}
		err := enc.Encode(&v)
		b := buf.Bytes()
		/*
			var b []byte
			var err error
			if !Debug || OnLambda {
				b, err = json.Marshal(v)
			} else {
				b, err = json.MarshalIndent(v, "", "  ")
			}
		*/
		if err != nil {
			return ErrorResponse(500, err.Error())
		}
		j = string(b)
	}

	return GenericResponse(j, "application/json")
}

type XmlMap map[string]any

func convertToXMLMap[T any](m map[string]T) XmlMap {
	ret := make(XmlMap)
	for k, v := range m {
		ret[k] = v
	}
	return ret
}

func (m XmlMap) MarshalXML(e *xml.Encoder, start xml.StartElement) error {

	if len(m) == 0 {
		return nil
	}

	err := e.EncodeToken(start)
	if err != nil {
		return err
	}

	for k, v := range m {
		// e.Encode(xmlMapEntry{XMLName: xml.Name{Local: k}, Value: v})
		switch v.(type) {
		case map[string]any:
			v = XmlMap(v.(map[string]any))
		case map[string]int:
			v = convertToXMLMap(v.(map[string]int))
		case map[string]float64:
			v = convertToXMLMap(v.(map[string]float64))
		case map[string]string:
			v = convertToXMLMap(v.(map[string]string))

		case []map[string]any:
			arr := v.([]map[string]any)
			varr := make([]XmlMap, len(arr))
			v = varr
			for i, m := range arr {
				varr[i] = XmlMap(m)
			}
		}

		e.EncodeElement(v, xml.StartElement{
			Name: xml.Name{Space: "", Local: k},
			Attr: nil,
		})
	}

	return e.EncodeToken(start.End())
}

// XMLResponse creates a xml response. The given object will be marshalled
// an its XML representation will be sent as the response's body-
// If indent is true, the XML will be indented, otherwise it will be a log one-liner
func XMLResponse(root string, data XmlMap, indent bool) Response {
	buf := new(bytes.Buffer)
	enc := xml.NewEncoder(buf)
	if indent {
		enc.Indent("", "    ")
	}
	if err := enc.EncodeElement(data, xml.StartElement{
		Name: xml.Name{Space: "", Local: root},
		Attr: nil,
	}); err != nil {
		return ErrorResponse(500, err.Error())
	}
	xml := string(buf.Bytes())

	return GenericResponse(xml, "application/xml")
}

// RedirectResponse creates a redirection response (HTTP status code 302)
// to the given URL
func RedirectResponse(url string) Response {
	return Response{
		Status:  302,
		Headers: map[string]string{"Location": url},
	}
}

// ErrorResponse creates an error response with the given status code and message
func ErrorResponse(status int, msg string) Response {
	m := map[string]string{"error": msg}
	b, err := json.Marshal(m)
	if err != nil {
		b = []byte("ErrorResponse; Wrong error message")
	}
	Request.Log.Write("Error: " + msg)
	return Response{
		Status:  status,
		Headers: map[string]string{"Content-Type": "application/json"},
		Body:    string(b),
	}
}

package gockham

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

var varsPat, _ = regexp.Compile("\\{([#\\?\\w]+)\\}")

const (
	varString = iota
	varInt    = iota
	varLang   = iota
)

// Action is an executable action mapped to an URL
type Action struct {
	Path     string               // Path mapped to this action
	Auth     func() bool          // Function that does authentication. Returns true if it was successful
	Signed   bool                 // Tells if the action can only be executed is URL is signed
	OnBegin  func() error         // An specific OnBegin for this action
	Fn       interface{}          // This is the actual action to execute. Has to be in the form: func(args ...interface{}) (Response,error) (can also return only a Response )
	OnEnd    func(resp *Response) // An specific OnEnd for this action
	regex    *regexp.Regexp       // regex that matches URLs mapped to this action
	varNames []string             // URL variable names
	vars     []int                // varString, varInt or varLang
}

// exec executes an Action though reflection
func (a Action) exec(params []interface{}) (Response, error) {
	funcType := reflect.TypeOf(a.Fn)
	in := make([]reflect.Value, funcType.NumIn())

	if funcType.NumIn() != len(params) {
		return ErrorResponse(500, "Wrong number of parameters in Fn"), nil
	}

	for i := 0; i < funcType.NumIn(); i++ {
		in[i] = reflect.ValueOf(params[i])
	}
	response := reflect.ValueOf(a.Fn).Call(in) // method.Call(in)

	var err error
	if len(response) > 1 && response[1].Interface() != nil {
		err = response[1].Interface().(error)
	}
	return response[0].Interface().(Response), err
}

func AddGet(action Action) Action {
	startRoutes["GET"] = append(startRoutes["GET"], action)
	return action
}

func AddPost(action Action) Action {
	startRoutes["POST"] = append(startRoutes["POST"], action)
	return action
}

func AddDelete(action Action) Action {
	startRoutes["DELETE"] = append(startRoutes["DELETE"], action)
	return action
}

func AddPut(action Action) Action {
	startRoutes["PUT"] = append(startRoutes["PUT"], action)
	return action
}

func AddQuery(action Action) Action {
	startRoutes["QUERY"] = append(startRoutes["QUERY"], action)
	return action
}

// Router decides which Action to execute
type Router struct {
	routes map[string][]Action
}

// AddGet, AddPost, AddDelete and AddPut use this
var startRoutes = map[string][]Action{
	"GET":    []Action{},
	"POST":   []Action{},
	"DELETE": []Action{},
	"PUT":    []Action{},
	"QUERY":  []Action{},
}

// NewRouter creates and initializes a Router
func NewRouter() Router {
	router := Router{
		routes: map[string][]Action{
			"GET":    []Action{},
			"POST":   []Action{},
			"DELETE": []Action{},
			"PUT":    []Action{},
			"QUERY":  []Action{},
		},
	}
	return router
}

func (r *Router) InitRoutes() {
	r.AddRoutes("GET", startRoutes["GET"]...)
	r.AddRoutes("POST", startRoutes["POST"]...)
	r.AddRoutes("DELETE", startRoutes["DELETE"]...)
	r.AddRoutes("PUT", startRoutes["PUT"]...)
	r.AddRoutes("QUERY", startRoutes["QUERY"]...)
}

// AddRoutes adds a route to the Router on a given method
func (r Router) AddRoutes(method string, actions ...Action) {
	for i := range actions {
		a := &actions[i]
		matches := varsPat.FindAllStringSubmatchIndex(a.Path, -1)
		a.vars = make([]int, len(matches))
		a.varNames = make([]string, len(matches))
		ptr := 0
		var pattern = ""
		for i, idxs := range matches {
			isInt := a.Path[idxs[2]] == '#'
			re := "([^/]+)"
			isOpt := a.Path[idxs[2]] == '?'
			if isOpt {
				re = "([^/]*)"
			} else if isInt {
				re = "(-?\\d+)"
			}
			pattern += a.Path[ptr:idxs[0]] + re
			ptr = idxs[3] + 1

			if isInt {
				a.varNames[i] = a.Path[idxs[2]+1 : idxs[3]]
				a.vars[i] = varInt
			} else if a.Path[idxs[2]:idxs[3]] == "lang" {
				a.varNames[i] = "lang"
				a.vars[i] = varLang
			} else {
				a.varNames[i] = a.Path[idxs[2]:idxs[3]]
				a.vars[i] = varString
			}
		}
		pattern += a.Path[ptr:]
		a.regex, _ = regexp.Compile(pattern)
		if a.OnBegin == nil {
			a.OnBegin = App.OnBeginReq
		}
		if a.OnEnd == nil {
			a.OnEnd = App.OnEndReq
		}
		if a.Auth == nil {
			a.Auth = AuthNone
		}

	}
	r.routes[method] = append(r.routes[method], actions...)
}

// Dispatch dispatches a request
func (r *Router) Dispatch() Response {
	method := Request.Event.HTTPMethod
	path := "/" + Request.Event.PathParameters["proxy"]

	// Try to decipher URL
	/*
		ciphered := false
		if path[1] == '~' {
			path = path[2:]
			b, err := DecodeUrl64(path)
			if err == nil {
				b = App.Crypt.AesDecrypt(b)
				if b[0] == '/' {
					path = string(b)
					ciphered = true
				}
			}
		}
	*/

	for _, route := range r.routes[method] {
		match := route.regex.FindAllStringSubmatch(path, -1)

		// We got a route that matches the path!
		if len(match) > 0 {
			// If it was posted Auth may be encoded on 'auth' body parameter
			if Request.Event.HTTPMethod == "POST" && Request.Auth.Subject == "" {
				params := Request.ExtractFormParamsFromBody()
				Request.Auth = CheckAuthToken(params["auth"])
			}

			if route.Signed {
				tokenStr := Request.Event.QueryStringParameters["signature"]
				token, err := App.ParseToken(tokenStr)
				// claims := token.Claims.(jwt.MapClaims)
				tokenPath := ""
				if token != nil {
					tokenPath = token.Claims.(jwt.MapClaims)["url"].(string)
				}
				if err != nil || !token.Valid || tokenPath != path {
					msg := "Wrong URL signature for " + path
					if err != nil {
						msg += ": " + err.Error()
					} else if !token.Valid {
						msg += ": Invalid token"
					} else {
						msg += fmt.Sprintf(": Path found in signature (%v) does not match %v", tokenPath, path)
					}

					if OnLambda || !Debug {
						return ErrorResponse(401, msg)
					}

					if Debug {
						Request.Log.Write(msg)
						Request.Log.Write("WARNING: Wrong URL signature, but allowed in development")
					}
				} else {
					Request.Signed = token.Claims.(jwt.MapClaims)
					Request.Log.Write(token.Claims)
				}
			}

			langPos := -1
			vars := make([]interface{}, len(match[0])-1)
			for i := 1; i < len(match[0]); i++ {
				// unescape url component. If not possible use original
				component, err := url.PathUnescape(match[0][i])
				if err != nil {
					component = match[0][i]
				}
				switch route.vars[i-1] {
				case varInt:
					vars[i-1], _ = strconv.Atoi(component)
				case varString:
					vars[i-1] = component
				case varLang:
					langPos = i - 1
					Request.Lang = component
				}
			}

			Request.Action = route
			Request.vars = vars

			// OnBegin is executed before Auth because it may need to access DB or other resources
			err := route.OnBegin()
			if err != nil {
				return ErrorResponse(500, err.Error())
			}

			if !route.Auth() {
				resp := ErrorResponse(401, "Authentication required")
				route.OnEnd(&resp) // OnEnd is executed, because OnBegin was executed before
				return resp
			}

			// If there is a lang variable, it is removed from the array
			if langPos != -1 {
				vars = append(vars[:langPos], vars[langPos+1:]...)
			}

			resp, err := route.exec(vars)
			Request.Log.AddValue("status", resp.Status)
			Request.Log.AddValue("length", len(resp.Body))
			route.OnEnd(&resp)
			if err != nil {
				return ErrorResponse(500, "Executing "+route.Path+": "+err.Error())
			}
			return resp
		}
	}
	msg := fmt.Sprintf("Dispatch: Path %v:%v not found", method, path)
	return ErrorResponse(404, msg)
}

func AuthNone() bool    { return true }
func AuthDefault() bool { return Request.Auth.Subject != "" }

// Access Control List
type Acl struct {
	Allow []string
	Deny  []string
}

// Map or roles to ACLs
var AclMap = map[string]Acl{}

// Set of possible permissions
var AclPerms = map[string]bool{}

// Extra ACL rules for a perm-role pair
var AclExtraRules = map[string]func() bool{}

// role can be a comma separated list of roles
func AclExtraRule(perm string, role string, rule func() bool) func() bool {
	roles := strings.Split(role, ",")
	for _, role := range roles {
		AclExtraRules[perm+"@"+role] = rule
	}
	return rule
}

// Reads a JSON file and initializes the ACL map
func InitAcl(file string) error {
	err := ReadJsonFile(file, &AclMap)
	if Debug {
		fmt.Printf("ACL: %v\n", AclMap)
	}
	return err
}

// AuthAcl returns a function that checks if a user has permission over a granted resource
func AuthAcl(perm string) func() bool {
	AclPerms[perm] = true
	return func() bool {
		return AuthAclClosure(perm)
	}
}

// AuthAclClosure checks if a user has a permission
func AuthAclClosure(perm string) bool {
	if Request.Auth.Subject == "" {
		return false
	}

	rolesUntyped := Request.Auth.Claims["roles"]
	if rolesUntyped == nil {
		return false
	}
	roles := rolesUntyped.([]any)
	for _, role := range roles {
		// fmt.Printf("authacl perm:%v role:%v\n", perm, role)
		acl, ok := AclMap[role.(string)]
		if ok {
			found, allow := func() (bool, bool) {
				if slices.Contains(acl.Deny, perm) {
					return true, false
				}
				if slices.Contains(acl.Allow, perm) {
					return true, true
				}
				if slices.Contains(acl.Deny, "all") {
					return true, false
				}
				if slices.Contains(acl.Allow, "all") {
					return true, true
				}
				return false, false
			}()
			if allow {
				extraRule, ok := AclExtraRules[perm+"@"+role.(string)]
				// The first extra rule that denies access is enough
				if ok && !extraRule() {
					return false
				}
			}
			// If we found a matching rule, we end here
			if found {
				return allow
			}
		}
	}
	return false
}

// Gets all permissions granted to a role
func AclRoleGrants(role string) []string {
	acl, ok := AclMap[role]
	granted := []string{}
	if ok {
		allowAll := slices.Contains(acl.Allow, "all")
		denyAll := slices.Contains(acl.Deny, "all")
		for perm := range AclPerms {
			add := false
			if !slices.Contains(acl.Deny, perm) {
				add = slices.Contains(acl.Allow, perm) || (!denyAll && allowAll)
			}
			if add {
				granted = append(granted, perm)
			}
		}
	}
	return granted
}

// ReadJsonFile reads a JSON file and unmarshals its content into the provided interface
func ReadJsonFile(file string, v interface{}) error {
	f, err := os.Open(file)
	if err == nil {
		defer f.Close()
		byteValue, err := io.ReadAll(f)
		if err == nil {
			err = json.Unmarshal(byteValue, v)
		}
	}
	return err
}

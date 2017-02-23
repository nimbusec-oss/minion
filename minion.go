package minion

import (
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gorilla/sessions"
)

func init() {
	gob.Register(Principal{})
}

const (
	// PrincipalKey is the key used for the principal in the user session.
	PrincipalKey = "_principal"

	// RedirectKey is the key used for the original URL before redirecting to the login site.
	RedirectKey = "_redirect"
)

// ErrorFormat defines as which content type an error should be serialized
type ErrorFormat string

const (
	// ErrorAsHTML formats an error using the HTML template `error.html`.
	ErrorAsHTML ErrorFormat = "html"
	// ErrorAsJSON formats the error as JSON object.
	ErrorAsJSON ErrorFormat = "json"
)

const (
	// TemplatePrincipalKey is the name templates can use to access the principal
	TemplatePrincipalKey = "principal"

	// TemplateFlashesKey is the name templates can use to access flash messages
	TemplateFlashesKey = "flashes"
)

// Logger is a simple interface to describe something that can write log output.
type Logger interface {
	Printf(fmt string, v ...interface{})
}

// Option is a functional configuration type that can be used to tailor
// the Minion instance during creation.
type Option func(*Minion) *Minion

// Minion implements basic building blocks that most http servers require
type Minion struct {
	Debug  bool
	Logger Logger

	// Unauthorized is called for Secured handlers where no authenticated
	// principal is found in the current session. The default handler will
	// redirect the user to `UnauthorizedURL` and store the original URL
	// in the session.
	Unauthorized    func(w http.ResponseWriter, r *http.Request)
	UnauthorizedURL string

	// Forbidden is called for Secured handlers where an authenticated principal
	// does not have enough permission to view the resource. The default handler
	// will execute the HTML template `ForbiddenTemplate`.
	Forbidden         func(w http.ResponseWriter, r *http.Request)
	ForbiddenTemplate string

	// Error is called for any error that occur during the request processing, be
	// it client side errors (4xx status) or server side errors (5xx status). The
	// default handler wirr execute the HTML template `ErrorTemplate`.
	Error         func(w http.ResponseWriter, r *http.Request, code int, err error)
	ErrorTemplate string

	sessions    sessions.Store
	sessionName string

	templates *template.Template
}

// NewMinion creates a new minion instance.
func NewMinion(options ...Option) Minion {
	m := &Minion{
		Debug:  os.Getenv("DEBUG") == "true",
		Logger: log.New(os.Stderr, "", log.LstdFlags),

		UnauthorizedURL:   "/login",
		ErrorTemplate:     "500.html",
		ForbiddenTemplate: "403.html",
	}

	// default handlers
	m.Unauthorized = m.defaultUnauthorizedHandler
	m.Forbidden = m.defaultForbiddenHandler
	m.Error = m.defaultErrorHandler

	// apply functional configuration
	for _, option := range options {
		m = option(m)
	}

	return *m
}

// Session can be used in the NewMinion function to add an secure cookie based session.
func Session(name string, key []byte, options *sessions.Options) Option {
	return func(m *Minion) *Minion {
		store := sessions.NewCookieStore(key)
		store.Options = options

		m.sessions = store
		m.sessionName = name
		return m
	}
}

func (m Minion) openSession(w http.ResponseWriter, r *http.Request) (*sessions.Session, error) {
	if m.sessions == nil {
		return nil, errors.New("no session store configured")
	}

	session, err := m.sessions.Get(r, m.sessionName)
	return session, err
}

// Get retrieves a value from the active session. If the value does not
// exist in the session, a provided default is returned
func (m Minion) Get(w http.ResponseWriter, r *http.Request, name string, def interface{}) interface{} {
	session, err := m.openSession(w, r)
	if err != nil {
		return def
	}
	value, ok := session.Values[name]
	if !ok {
		return def
	}
	return value
}

// Set stores a value in the active session.
func (m Minion) Set(w http.ResponseWriter, r *http.Request, name string, value interface{}) {
	session, err := m.openSession(w, r)
	if err != nil {
		return
	}

	session.Values[name] = value
}

// Delete removes a value from the active session.
func (m Minion) Delete(w http.ResponseWriter, r *http.Request, name string) {
	session, err := m.openSession(w, r)
	if err != nil {
		return
	}

	delete(session.Values, name)
}

// ClearSession removes all values from the active session.
func (m Minion) ClearSession(w http.ResponseWriter, r *http.Request) {
	session, err := m.openSession(w, r)
	if err != nil {
		return
	}

	for name := range session.Values {
		delete(session.Values, name)
	}
}

// AddFlash adds a flash message to the session.
func (m Minion) AddFlash(w http.ResponseWriter, r *http.Request, value interface{}) {
	session, err := m.openSession(w, r)
	if err != nil {
		return
	}

	session.AddFlash(value)
}

// Flashes returns a slice of flash messages from the session.
func (m Minion) Flashes(w http.ResponseWriter, r *http.Request) []interface{} {
	session, err := m.openSession(w, r)
	if err != nil {
		return nil
	}

	flashes := session.Flashes()
	return flashes
}

func (m Minion) SaveSession(w http.ResponseWriter, r *http.Request) {
	session, err := m.openSession(w, r)
	if err != nil {
		m.Logger.Printf("session open: %v", err)
		return
	}

	err = session.Save(r, w)
	if err != nil {
		m.Logger.Printf("session save: %v", err)
		return
	}
}

// Secured requires that the user has at least one of the provided roles before
// the request is forwarded to the secured handler.
func (m Minion) Secured(fn http.HandlerFunc, roles ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal := m.Get(w, r, PrincipalKey, Principal{}).(Principal)
		if !principal.Authenticated {
			m.Unauthorized(w, r)
			return
		}

		if !principal.HasAnyRole(roles...) {
			m.Forbidden(w, r)
			return
		}

		fn(w, r)
	}
}

// defaultUnauthorizedHandler is the default handler for minion.Unauthorized
func (m *Minion) defaultUnauthorizedHandler(w http.ResponseWriter, r *http.Request) {
	session, err := m.openSession(w, r)
	if err != nil {
		m.Error(w, r, http.StatusBadRequest, err)
		return
	}

	session.Values[RedirectKey] = r.URL.String()
	err = session.Save(r, w)
	if err != nil {
		m.Error(w, r, http.StatusInternalServerError, err)
		return
	}

	http.Redirect(w, r, m.UnauthorizedURL, http.StatusSeeOther)
}

// defaultForbiddenHandler is the default handler for minion.Forbidden
func (m *Minion) defaultForbiddenHandler(w http.ResponseWriter, r *http.Request) {
	m.HTML(w, r, http.StatusForbidden, m.ForbiddenTemplate, V{})
}

// defaultErrorHandler is the default handler for minion.Error
func (m *Minion) defaultErrorHandler(w http.ResponseWriter, r *http.Request, code int, err error) {
	m.Logger.Printf("error: %v", err)
	m.HTML(w, r, code, m.ErrorTemplate, V{
		"code":  code,
		"error": err.Error(),
	})
}

// JSON outputs the data encoded as JSON.
func (m Minion) JSON(w http.ResponseWriter, r *http.Request, code int, data interface{}) {
	m.SaveSession(w, r)
	w.Header().Add("content-type", "application/json; charset=utf-8")
	w.WriteHeader(code)

	err := json.NewEncoder(w).Encode(data)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "failed to encode json: %v", err)
		m.Logger.Printf("failed to encode json: %v", err)
	}
}

// HTML outputs a rendered HTML template to the client. This function also includes
// some default variables into the template scope.
func (m *Minion) HTML(w http.ResponseWriter, r *http.Request, code int, name string, data V) {
	// reload templates in debug mode
	if m.templates == nil || m.Debug {
		fm := template.FuncMap{
			"div": func(dividend, divisor int) float64 {
				return float64(dividend) / float64(divisor)
			},
			"json": func(v interface{}) template.JS {
				b, _ := json.MarshalIndent(v, "", "  ")
				return template.JS(b)
			},
			"dict": func(values ...interface{}) (map[string]interface{}, error) {
				if len(values)%2 != 0 {
					return nil, errors.New("invalid dict call")
				}
				dict := make(map[string]interface{}, len(values)/2)
				for i := 0; i < len(values); i += 2 {
					key, ok := values[i].(string)
					if !ok {
						return nil, errors.New("dict keys must be strings")
					}
					dict[key] = values[i+1]
				}
				return dict, nil
			},
		}

		var err error
		m.templates, err = template.New("").Funcs(fm).ParseGlob("templates/*")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "failed to parse templates: %v", err)
			m.Logger.Printf("failed to parse templates: %v", err)
			return
		}
	}

	flashes := m.Flashes(w, r)
	data[TemplateFlashesKey] = flashes

	principal := m.Get(w, r, PrincipalKey, Principal{}).(Principal)
	data[TemplatePrincipalKey] = principal

	m.SaveSession(w, r)
	w.Header().Add("content-type", "text/html; charset=utf-8")
	w.WriteHeader(code)

	err := m.templates.ExecuteTemplate(w, name, data)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "failed to execute template %q: %v", name, err)
		m.Logger.Printf("failed to execute template %q: %v", name, err)
		return
	}
}

// Principal is an entity that can be authenticated and verified.
type Principal struct {
	Authenticated bool
	TwoFactor     bool
	ID            string
	Login         string
	Roles         string
}

// HasAnyRole checks whether the principal has any of the given roles. Use '*'
// as a wildcard role to match any.
func (u Principal) HasAnyRole(roles ...string) bool {
	if !u.Authenticated {
		return false
	}

	dedup := make(map[string]struct{})
	for _, role := range strings.Split(u.Roles, " ") {
		dedup[role] = struct{}{}
	}

	for _, role := range roles {
		if _, ok := dedup[role]; ok || role == "*" {
			return true
		}
	}

	return false
}

// BindingResult holds validation errors of the binding process from a HTML
// form to a Go struct.
type BindingResult map[string]string

// Valid returns whether the binding was successfull or not.
func (br BindingResult) Valid() bool {
	return len(br) == 0
}

// Fail marks the binding as failed and stores an error for the given field
// that caused the form binding to fail.
func (br BindingResult) Fail(field, err string) {
	br[field] = err
}

// Include copies all errors and state of a binding result
func (br BindingResult) Include(other BindingResult) {
	for field, err := range other {
		br.Fail(field, err)
	}
}

// V is a helper type to quickly build variable maps for templates.
type V map[string]interface{}

// MarshalJSON implements the json.Marshaler interface.
func (v V) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}(v))
}

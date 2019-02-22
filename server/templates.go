package server

import (
	"bytes"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

const (
	tmplApproval = "approval.html"
	tmplLogin    = "login.html"
	tmplPassword = "password.html"
	tmplOOB      = "oob.html"
	tmplError    = "error.html"
	tmplHeader   = "header.html"
	tmplFooter   = "footer.html"
)

type templates struct {
	loginTmpl    *template.Template
	approvalTmpl *template.Template
	passwordTmpl *template.Template
	oobTmpl      *template.Template
	errorTmpl    *template.Template
}

type webConfig struct {
	themeDir     http.FileSystem
	staticDir    http.FileSystem
	templatesDir http.FileSystem
	logoURL      string
	issuer       string
	theme        string
	issuerURL    string
	extra        map[string]string
}

// func join(basepath string, paths ...string) string {
// 	u, _ := url.Parse(basepath)
// 	u.Path = path.Join(append([]string{u.Path}, paths...)...)
// 	return u.String()
// }

// loadTemplates parses the expected templates from the provided directory.
func loadTemplates(c WebConfig, issuerURL string) (*templates, error) {
	if c.Theme == "" {
		c.Theme = "coreos"
	}

	if c.Issuer == "" {
		c.Issuer = "dex"
	}

	if c.LogoURL == "" {
		c.LogoURL = "theme/logo.png"
	}

	funcs := template.FuncMap{
		"issuer": func() string { return c.Issuer },
		"logo":   func() string { return c.LogoURL },
		// "static": func(s string) string { return relativeURL(issuerURL, "static", s) },
		// "theme":  func(s string) string { return relativeURL(issuerURL, "themes", c.Theme, s) },
		"url":   func(reqPath, assetPath string) string { return relativeURL(issuerURL, reqPath, assetPath) },
		"lower": strings.ToLower,
		"extra": func(k string) string { return c.Extra[k] },
	}

	group := template.New("")

	// load all of our templates individually.
	// some http.FilSystem implementations don't implement Readdir

	loginTemplate, err := loadTemplate(c.Dir, tmplLogin, funcs, group)
	if err != nil {
		return nil, err
	}

	approvalTemplate, err := loadTemplate(c.Dir, tmplApproval, funcs, group)
	if err != nil {
		return nil, err
	}

	passwordTemplate, err := loadTemplate(c.Dir, tmplPassword, funcs, group)
	if err != nil {
		return nil, err
	}

	// funcs := map[string]interface{}{
	// 	"issuer": func() string { return c.issuer },
	// 	"logo":   func() string { return c.logoURL },
	// 	"url":    func(reqPath, assetPath string) string { return relativeURL(issuerURL.Path, reqPath, assetPath) },
	// 	"lower":  strings.ToLower,
	// 	"extra":  func(k string) string { return c.extra[k] },
	// =======
	oobTemplate, err := loadTemplate(c.Dir, tmplOOB, funcs, group)
	if err != nil {
		return nil, err
	}

	errorTemplate, err := loadTemplate(c.Dir, tmplError, funcs, group)
	if err != nil {
		return nil, err
	}

	_, err = loadTemplate(c.Dir, tmplHeader, funcs, group)
	if err != nil {
		// we don't actually care if this template exists
	}

	_, err = loadTemplate(c.Dir, tmplFooter, funcs, group)
	if err != nil {
		// we don't actually care if this template exists
	}

	return &templates{
		loginTmpl:    loginTemplate,
		approvalTmpl: approvalTemplate,
		passwordTmpl: passwordTemplate,
		oobTmpl:      oobTemplate,
		errorTmpl:    errorTemplate,
	}, nil
}

// relativeURL returns the URL of the asset relative to the URL of the request path.
// The serverPath is consulted to trim any prefix due in case it is not listening
// to the root path.
//
// Algorithm:
// 1. Remove common prefix of serverPath and reqPath
// 2. Remove common prefix of assetPath and reqPath
// 3. For each part of reqPath remaining(minus one), go up one level (..)
// 4. For each part of assetPath remaining, append it to result
//
//eg
//server listens at localhost/dex so serverPath is dex
//reqPath is /dex/auth
//assetPath is static/main.css
//relativeURL("/dex", "/dex/auth", "static/main.css") = "../static/main.css"
func relativeURL(serverPath, reqPath, assetPath string) string {
	splitPath := func(p string) []string {
		res := []string{}
		parts := strings.Split(path.Clean(p), "/")
		for _, part := range parts {
			if part != "" {
				res = append(res, part)
			}
		}
		return res
	}

	stripCommonParts := func(s1, s2 []string) ([]string, []string) {
		min := len(s1)
		if len(s2) < min {
			min = len(s2)
		}

		splitIndex := min
		for i := 0; i < min; i++ {
			if s1[i] != s2[i] {
				splitIndex = i
				break
			}
		}
		return s1[splitIndex:], s2[splitIndex:]
	}

	server, req, asset := splitPath(serverPath), splitPath(reqPath), splitPath(assetPath)

	// Remove common prefix of request path with server path
	// nolint: ineffassign
	server, req = stripCommonParts(server, req)

	// Remove common prefix of request path with asset path
	asset, req = stripCommonParts(asset, req)

	// For each part of the request remaining (minus one) -> go up one level (..)
	// For each part of the asset remaining               -> append it
	var relativeURL string
	for i := 0; i < len(req)-1; i++ {
		relativeURL = path.Join("..", relativeURL)
	}
	relativeURL = path.Join(relativeURL, path.Join(asset...))

	return relativeURL
}

// load a template by name from the templates dir
func loadTemplate(dir http.FileSystem, name string, funcs template.FuncMap, group *template.Template) (*template.Template, error) {
	file, err := dir.Open(filepath.Join("templates", name))
	if err != nil {
		return nil, err
	}

	defer file.Close()

	var buffer bytes.Buffer
	buffer.ReadFrom(file)
	contents := buffer.String()

	return group.New(name).Funcs(funcs).Parse(contents)
}

var scopeDescriptions = map[string]string{
	"offline_access": "Have offline access",
	"profile":        "View basic profile information",
	"email":          "View your email address",
}

type connectorInfo struct {
	ID   string
	Name string
	URL  string
	Type string
}

type byName []connectorInfo

func (n byName) Len() int           { return len(n) }
func (n byName) Less(i, j int) bool { return n[i].Name < n[j].Name }
func (n byName) Swap(i, j int)      { n[i], n[j] = n[j], n[i] }

func (t *templates) login(r *http.Request, w http.ResponseWriter, connectors []connectorInfo, reqPath string) error {
	sort.Sort(byName(connectors))
	data := struct {
		Connectors []connectorInfo
		ReqPath    string
	}{connectors, r.URL.Path}
	return renderTemplate(w, t.loginTmpl, data)
}

func (t *templates) password(r *http.Request, w http.ResponseWriter, postURL, lastUsername, usernamePrompt string, lastWasInvalid, showBacklink bool, reqPath string) error {
	data := struct {
		PostURL        string
		BackLink       bool
		Username       string
		UsernamePrompt string
		Invalid        bool
		ReqPath        string
	}{postURL, showBacklink, lastUsername, usernamePrompt, lastWasInvalid, r.URL.Path}
	return renderTemplate(w, t.passwordTmpl, data)
}

func (t *templates) approval(r *http.Request, w http.ResponseWriter, authReqID, username, clientName string, scopes []string, reqPath string) error {
	accesses := []string{}
	for _, scope := range scopes {
		access, ok := scopeDescriptions[scope]
		if ok {
			accesses = append(accesses, access)
		}
	}
	sort.Strings(accesses)
	data := struct {
		User      string
		Client    string
		AuthReqID string
		Scopes    []string
		ReqPath   string
	}{username, clientName, authReqID, accesses, r.URL.Path}
	return renderTemplate(w, t.approvalTmpl, data)
}

func (t *templates) oob(r *http.Request, w http.ResponseWriter, code string, reqPath string) error {
	data := struct {
		Code    string
		ReqPath string
	}{code, r.URL.Path}
	return renderTemplate(w, t.oobTmpl, data)
}

func (t *templates) err(r *http.Request, w http.ResponseWriter, errCode int, errMsg string) error {
	w.WriteHeader(errCode)
	data := struct {
		ErrType string
		ErrMsg  string
		ReqPath string
	}{http.StatusText(errCode), errMsg, r.URL.Path}
	if err := t.errorTmpl.Execute(w, data); err != nil {
		return fmt.Errorf("Error rendering template %s: %s", t.errorTmpl.Name(), err)
	}
	return nil
}

// small io.Writer utility to determine if executing the template wrote to the underlying response writer.
type writeRecorder struct {
	wrote bool
	w     io.Writer
}

func (w *writeRecorder) Write(p []byte) (n int, err error) {
	w.wrote = true
	return w.w.Write(p)
}

func renderTemplate(w http.ResponseWriter, tmpl *template.Template, data interface{}) error {
	wr := &writeRecorder{w: w}
	if err := tmpl.Execute(wr, data); err != nil {
		if !wr.wrote {
			// TODO(ericchiang): replace with better internal server error.
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return fmt.Errorf("Error rendering template %s: %s", tmpl.Name(), err)
	}
	return nil
}

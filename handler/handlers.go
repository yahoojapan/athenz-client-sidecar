package handler

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httputil"

	ntokend "ghe.corp.yahoo.co.jp/athenz/athenz-ntokend"
	"ghe.corp.yahoo.co.jp/athenz/athenz-tenant-sidecar/config"
	"ghe.corp.yahoo.co.jp/athenz/athenz-tenant-sidecar/model"
	"ghe.corp.yahoo.co.jp/athenz/athenz-tenant-sidecar/service"
)

// Handler for handling a set of HTTP requests.
type Handler interface {
	// NToken handles get n-token requests.
	NToken(http.ResponseWriter, *http.Request) error
	// NTokenProxy handles proxy requests that require a n-token.
	NTokenProxy(http.ResponseWriter, *http.Request) error
	// RoleToken handles get role token requests.
	RoleToken(http.ResponseWriter, *http.Request) error
	// RoleTokenProxy handles proxy requests that require a role token.
	RoleTokenProxy(http.ResponseWriter, *http.Request) error
}

// Func is http.HandlerFunc with error return.
type Func func(http.ResponseWriter, *http.Request) error

// handler is internal implementation of Handler interface.
type handler struct {
	proxy *httputil.ReverseProxy
	token ntokend.TokenProvider
	role  service.RoleProvider
	cfg   config.Proxy
}

// New creates a handler for handling different HTTP requests based on the given services. It also contains a reverse proxy for handling proxy request.
func New(cfg config.Proxy, bp httputil.BufferPool, token ntokend.TokenProvider, role service.RoleProvider) Handler {
	return &handler{
		proxy: &httputil.ReverseProxy{
			BufferPool: bp,
		},
		token: token,
		role:  role,
		cfg:   cfg,
	}
}

// NToken handles n-token requests and responses the corresponding n-token. Depends on token service.
func (h *handler) NToken(w http.ResponseWriter, r *http.Request) error {
	defer flushAndClose(r.Body)

	tok, err := h.token()
	if err != nil {
		return err
	}

	return json.NewEncoder(w).Encode(model.NTokenResponse{
		NToken: tok,
	})
}

// NTokenProxy attaches n-token to HTTP requests and proxies it. Depends on token service.
func (h *handler) NTokenProxy(w http.ResponseWriter, r *http.Request) error {
	defer flushAndClose(r.Body)

	tok, err := h.token()
	if err != nil {
		return err
	}
	r.Header.Set(h.cfg.AuthHeader, tok)
	h.proxy.ServeHTTP(w, r)
	return nil
}

// RoleToken handles role token requests and responses the corresponding role token. Depends on role token service.
func (h *handler) RoleToken(w http.ResponseWriter, r *http.Request) error {
	defer flushAndClose(r.Body)

	var data model.RoleRequest
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		return err
	}
	tok, err := h.role(r.Context(), data.Domain, data.Role, data.ProxyForPrincipal, data.MinExpiry, data.MaxExpiry)
	if err != nil {
		return err
	}

	return json.NewEncoder(w).Encode(tok)
}

// RoleTokenProxy attaches role token to HTTP requests and proxies it. Depends on role token service.
func (h *handler) RoleTokenProxy(w http.ResponseWriter, r *http.Request) error {
	defer flushAndClose(r.Body)

	role := r.Header.Get("Athenz-Role-Auth")
	domain := r.Header.Get("Athenz-Domain-Auth")
	principal := r.Header.Get("Athenz-Proxy-Principal-Auth")
	tok, err := h.role(r.Context(), domain, role, principal, 0, 0)
	if err != nil {
		return err
	}
	r.Header.Set(h.cfg.RoleHeader, tok.Token)
	h.proxy.ServeHTTP(w, r)
	return nil
}

// flushAndClose helps to flush and close a ReadCloser. Used for request body internal.
// Returns if there is any errors.
func flushAndClose(rc io.ReadCloser) error {
	if rc != nil {
		// flush
		_, err := io.Copy(ioutil.Discard, rc)
		if err != nil {
			return err
		}
		// close
		return rc.Close()
	}
	return nil
}

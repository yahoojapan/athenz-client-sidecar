/*
Copyright (C)  2018 Yahoo Japan Corporation Athenz team.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package handler

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httputil"

	"github.com/kpango/ntokend"
	"github.com/yahoojapan/athenz-client-sidecar/v2/config"
	"github.com/yahoojapan/athenz-client-sidecar/v2/model"
	"github.com/yahoojapan/athenz-client-sidecar/v2/service"
)

// Handler for handling a set of HTTP requests.
type Handler interface {
	// NToken handles get N-token requests.
	NToken(http.ResponseWriter, *http.Request) error
	// NTokenProxy handles proxy requests that require a N-token.
	NTokenProxy(http.ResponseWriter, *http.Request) error
	// AccessToken handles post access token requests.
	AccessToken(http.ResponseWriter, *http.Request) error
	// RoleToken handles post role token requests.
	RoleToken(http.ResponseWriter, *http.Request) error
	// RoleTokenProxy handles proxy requests that require a role token.
	RoleTokenProxy(http.ResponseWriter, *http.Request) error
	// ServiceCert handles get svccert requests.
	ServiceCert(http.ResponseWriter, *http.Request) error
}

// Func is http.HandlerFunc with error return.
type Func func(http.ResponseWriter, *http.Request) error

// handler is internal implementation of Handler interface.
type handler struct {
	proxy   *httputil.ReverseProxy
	token   ntokend.TokenProvider
	access  service.AccessProvider
	role    service.RoleProvider
	svcCert service.SvcCertProvider
	cfg     config.Proxy
}

// New creates a handler for handling different HTTP requests based on the given services. It also contains a reverse proxy for handling proxy request.
func New(cfg config.Proxy, bp httputil.BufferPool, token ntokend.TokenProvider, access service.AccessProvider, role service.RoleProvider, svcCert service.SvcCertProvider) Handler {
	return &handler{
		proxy: &httputil.ReverseProxy{
			BufferPool: bp,
		},
		token:   token,
		access:  access,
		role:    role,
		cfg:     cfg,
		svcCert: svcCert,
	}
}

// NToken handles N-token requests and responses the corresponding N-token. Depends on token service.
func (h *handler) NToken(w http.ResponseWriter, r *http.Request) error {
	defer flushAndClose(r.Body)

	tok, err := h.token()
	if err != nil {
		return err
	}

	w.Header().Set("Content-type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(model.NTokenResponse{
		NToken: tok,
	})
}

// NTokenProxy attaches N-token to HTTP requests and proxies it. Depends on token service.
func (h *handler) NTokenProxy(w http.ResponseWriter, r *http.Request) error {
	defer flushAndClose(r.Body)

	tok, err := h.token()
	if err != nil {
		return err
	}
	r.Header.Set(h.cfg.PrincipalAuthHeader, tok)
	h.proxy.ServeHTTP(w, r)
	return nil
}

// AccessToken handles access token requests and responses the corresponding access token. Depends on access token service.
func (h *handler) AccessToken(w http.ResponseWriter, r *http.Request) error {
	defer flushAndClose(r.Body)

	var data model.AccessRequest
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		return err
	}
	tok, err := h.access(r.Context(), data.Domain, data.Role, data.ProxyForPrincipal, data.Expiry)
	if err != nil {
		return err
	}

	w.Header().Set("Content-type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(tok)
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

	w.Header().Set("Content-type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(tok)
}

// RoleTokenProxy attaches role token to HTTP requests and proxies it. Depends on role token service.
func (h *handler) RoleTokenProxy(w http.ResponseWriter, r *http.Request) error {
	defer flushAndClose(r.Body)

	role := r.Header.Get("Athenz-Role")
	domain := r.Header.Get("Athenz-Domain")
	principal := r.Header.Get("Athenz-Proxy-Principal")
	tok, err := h.role(r.Context(), domain, role, principal, 0, 0)
	if err != nil {
		return err
	}
	r.Header.Set(h.cfg.RoleAuthHeader, tok.Token)
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

// ServiceCert handles certificate requests and responses the corresponding certificate. Depends on svcCert service.
func (h *handler) ServiceCert(w http.ResponseWriter, r *http.Request) error {
	defer flushAndClose(r.Body)

	cert, err := h.svcCert()
	if err != nil {
		return err
	}

	w.Header().Set("Content-type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(model.SvcCertResponse{
		Cert: cert,
	})
}

package handler

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"math"
	"net/http"
	"net/http/httputil"
	"sync"
	"sync/atomic"

	"ghe.corp.yahoo.co.jp/athenz/athenz-tenant-sidecar/config"
	"ghe.corp.yahoo.co.jp/athenz/athenz-tenant-sidecar/model"
	"ghe.corp.yahoo.co.jp/athenz/athenz-tenant-sidecar/service"
	"ghe.corp.yahoo.co.jp/yusukato/gocred"
)

type Handler interface {
	NToken(http.ResponseWriter, *http.Request) error
	NTokenProxy(http.ResponseWriter, *http.Request) error
	HCC(http.ResponseWriter, *http.Request) error
	UDB(http.ResponseWriter, *http.Request) error
}

type Func func(http.ResponseWriter, *http.Request) error

type handler struct {
	proxy *httputil.ReverseProxy
	udb   service.UDB
	token service.TokenProvider
	crt   service.CertProvider
	cfg   config.Proxy
}

type buffer struct {
	pool sync.Pool
	size *int64
}

const (
	ContentType     = "Content-Type"
	ApplicationJSON = "application/json"
	CharsetUTF8     = "charset=UTF-8"
	ncookie         = "N"
	tcookie         = "T"
)

func newBuffer(size int64) httputil.BufferPool {
	if size == 0 {
		return nil
	}
	return &buffer{
		pool: sync.Pool{
			New: func() interface{} {
				return make([]byte, 0, size)
			},
		},
		size: &size,
	}
}

func (b *buffer) Get() []byte {
	return b.pool.Get().([]byte)
}

func (b *buffer) Put(buf []byte) {
	size := atomic.LoadInt64(b.size)
	if len(buf) >= int(size) || cap(buf) >= int(size) {
		size = int64(math.Max(float64(len(buf)), float64(cap(buf))))
		buf = make([]byte, 0, size)
		atomic.StoreInt64(b.size, size)
	}
	b.pool.Put(buf[:0])
}

func New(cfg config.Proxy, u service.UDB, token service.TokenProvider, crt service.CertProvider) Handler {
	return &handler{
		proxy: &httputil.ReverseProxy{
			BufferPool: newBuffer(cfg.BufferSize),
		},
		udb:   u,
		token: token,
		crt:   crt,
		cfg:   cfg,
	}
}

func (h *handler) NToken(w http.ResponseWriter, r *http.Request) error {
	tok, err := h.token()
	if err != nil {
		return err
	}

	return json.NewEncoder(w).Encode(struct {
		NToken string `json:"n_token"`
	}{
		NToken: tok,
	})
}

func (h *handler) NTokenProxy(w http.ResponseWriter, r *http.Request) error {
	defer func() {
		if r.Body != nil {
			io.Copy(ioutil.Discard, r.Body)
			r.Body.Close()
		}
	}()
	tok, err := h.token()
	if err != nil {
		return err
	}
	r.Header.Set(h.cfg.AuthHeader, tok)
	h.proxy.ServeHTTP(w, r)
	return nil
}

func (h *handler) HCC(w http.ResponseWriter, r *http.Request) error {
	defer func() {
		if r.Body != nil {
			io.Copy(ioutil.Discard, r.Body)
			r.Body.Close()
		}
	}()

	var data model.HCCRequest
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		return err
	}
	crt, err := h.crt(data.AppID)
	if err != nil {

		return err
	}

	return json.NewEncoder(w).Encode(struct {
		Certificate string `json:"certificate"`
	}{
		Certificate: crt,
	})
}

func (h *handler) UDB(w http.ResponseWriter, r *http.Request) error {
	defer func() {
		if r.Body != nil {
			io.Copy(ioutil.Discard, r.Body)
			r.Body.Close()
		}
	}()

	var data model.UDBRequest
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		return err
	}

	cred, err := gocred.New(data.NCookie, data.TCookie, data.KeyID, data.KeyData)
	if err != nil {
		return err
	}

	res, err := h.udb.GetByGUID(data.AppID, cred.GUID(), data.Keys)
	if err != nil {
		return err
	}

	return json.NewEncoder(w).Encode(res)
}

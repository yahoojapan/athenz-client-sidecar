package handler

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"

	"ghe.corp.yahoo.co.jp/athenz/hcc-k8s/config"
	"ghe.corp.yahoo.co.jp/athenz/hcc-k8s/model"
	"ghe.corp.yahoo.co.jp/athenz/hcc-k8s/service"
	"ghe.corp.yahoo.co.jp/yusukato/gocred"
)

type Handler interface {
	NToken(http.ResponseWriter, *http.Request) error
	HCC(http.ResponseWriter, *http.Request) error
	NTokenProxy(http.ResponseWriter, *http.Request) error
	UDB(http.ResponseWriter, *http.Request) error
}

type Func func(http.ResponseWriter, *http.Request) error

type handler struct {
	udb   service.UDB
	token service.TokenProvider
	cfg   config.Cookie
	crt   service.CertProvider
}

const (
	ContentType     = "Content-Type"
	ApplicationJSON = "application/json"
	CharsetUTF8     = "charset=UTF-8"
	ncookie         = "N"
	tcookie         = "T"
)

func New(u service.UDB, cfg config.Cookie, token service.TokenProvider, crt service.CertProvider) Handler {
	return &handler{
		udb:   u,
		cfg:   cfg,
		token: token,
		crt:   crt,
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

func (h *handler) NTokenProxy(w http.ResponseWriter, r *http.Request) error {
	return nil
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

	res, err := h.udb.GetByGUID(cred.GUID())
	if err != nil {
		return err
	}

	return json.NewEncoder(w).Encode(res)
}

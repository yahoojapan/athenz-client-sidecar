package handler

import (
	"net/http"

	"ghe.corp.yahoo.co.jp/athenz/hcc-k8s/config"
	"ghe.corp.yahoo.co.jp/athenz/hcc-k8s/service"
)

type Handler interface {
	NToken(http.ResponseWriter, *http.Request) error
	HCC(http.ResponseWriter, *http.Request) error
	NTokenProxy(http.ResponseWriter, *http.Request) error
	UDBProxy(http.ResponseWriter, *http.Request) error
}

type Func func(http.ResponseWriter, *http.Request) error

type handler struct {
	udb service.UDB
	enc service.Encrypter
	cfg config.Cookie
}

const (
	ContentType     = "Content-Type"
	ApplicationJSON = "application/json"
	CharsetUTF8     = "charset=UTF-8"
	ncookie         = "N"
	tcookie         = "T"
)

func New(u service.UDB, e service.Encrypter, cfg config.Cookie) Handler {
	return &handler{
		udb: u,
		enc: e,
		cfg: cfg,
	}
}

func (h *handler) NToken(http.ResponseWriter, *http.Request) error {
	return nil
}

func (h *handler) HCC(http.ResponseWriter, *http.Request) error {
	return nil
}

func (h *handler) NTokenProxy(http.ResponseWriter, *http.Request) error {
	return nil
}

func (h *handler) UDBProxy(http.ResponseWriter, *http.Request) error {
	return nil
}

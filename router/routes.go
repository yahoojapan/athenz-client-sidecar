package router

import (
	"net/http"

	"ghe.corp.yahoo.co.jp/athenz/hcc-k8s/handler"
)

type Route struct {
	Name        string
	Methods     []string
	Pattern     string
	HandlerFunc handler.Func
}

func NewRoutes(h handler.Handler) []Route {
	return []Route{
		{
			"NToken Handler",
			[]string{
				http.MethodGet,
			},
			"/ntoken",
			h.NToken,
		},
		{
			"NToken proxy Handler",
			[]string{
				"*",
			},
			"/ntoken/proxy",
			h.NTokenProxy,
		},
		{
			"HCC Handler",
			[]string{
				http.MethodGet,
				http.MethodPost,
			},
			"/hcc",
			h.HCC,
		},
		{
			"UDB",
			[]string{
				"*",
			},
			"/udb",
			h.UDB,
		},
	}
}

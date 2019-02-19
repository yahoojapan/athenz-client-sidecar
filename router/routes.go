package router

import (
	"net/http"

	"github.com/yahoojapan/athenz-client-sidecar/handler"
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
			"RoleToken Handler",
			[]string{
				http.MethodPost,
			},
			"/roletoken",
			h.RoleToken,
		},
		{
			"RoleToken proxy Handler",
			[]string{
				"*",
			},
			"/proxy/roletoken",
			h.RoleTokenProxy,
		},
		{
			"NToken proxy Handler",
			[]string{
				"*",
			},
			"/proxy/ntoken",
			h.NTokenProxy,
		},
	}
}

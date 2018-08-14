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
			"Demographic Handler",
			[]string{
				http.MethodGet,
			},
			"/hcc",
			h.Demographic,
		},
	}
}

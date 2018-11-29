package model

import (
	"time"

	"ghe.corp.yahoo.co.jp/athenz/athenz-tenant-sidecar/service"
)

// RoleRequest represent the request information to get the role token.
type RoleRequest struct {
	// Domain represent the domain field of the request.
	Domain string `json:"domain"`

	// Role represent the role field of the request.
	Role string `json:"role"`

	// ProxyForPrincipal represent the ProxyForPrincipal field of the request.
	ProxyForPrincipal string `json:"proxy_for_principal"`

	// MinExpiry represent the MinExpiry field of the request.
	MinExpiry time.Duration `json:"min_expiry"`

	// MaxExpiry represent the MaxExpiry field of the request.
	MaxExpiry time.Duration `json:"max_expiry"`
}

// RoleResponse represent the basic information of the role token.
type RoleResponse = service.RoleToken

// NTokenResponse represent the response information of get N-token request.
type NTokenResponse struct {
	// NToken represent the N-token generated.
	NToken string `json:"token"`
}

package model

import "time"

// HCRequest represent the Host Certificate request information.
type HCRequest struct {
	// AppID represent Host Certificate application ID.
	AppID string `json:"app_id"`
}

// UDBRequest represent the User Database request information.
type UDBRequest struct {
	// AppId represent User Database application ID.
	AppID string `json:"app_id"`

	// NCookie represent the N-Cookie string to connect to User Database.
	NCookie string `json:"n_cookie"`

	// TCookie represent the T-Cookie string to connect to User Database.
	TCookie string `json:"t_cookie"`

	// KeyID represent the Key ID to connect to User Database.
	KeyID string `json:"key_id"`

	// KeyData represent the Key Data to connect to User Database.
	KeyData string `json:"key_data"`

	// Keys represent the elements get from User Database.
	Keys []string `json:"keys"`
}

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

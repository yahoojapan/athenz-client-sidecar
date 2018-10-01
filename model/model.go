package model

import "time"

type HCRequest struct {
	AppID string `json:"app_id"`
}

type UDBRequest struct {
	AppID   string   `json:"app_id"`
	NCookie string   `json:"n_cookie"`
	TCookie string   `json:"t_cookie"`
	KeyID   string   `json:"key_id"`
	KeyData string   `json:"key_data"`
	Keys    []string `json:"keys"`
}

type RoleRequest struct {
	Domain            string        `json:"domain"`
	Role              string        `json:"role"`
	ProxyForPrincipal string        `json:"proxy_for_principal"`
	MinExpiry         time.Duration `json:"min_expiry"`
	MaxExpiry         time.Duration `json:"max_expiry"`
}

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
package model

import (
	"github.com/yahoojapan/athenz-client-sidecar/service"
)

// AccessRequest represents the request information to retrieve the access token.
type AccessRequest struct {
	// Domain represents the domain field of the request.
	Domain string `json:"domain"`

	// Role represents the role field of the request.
	Role string `json:"role"`

	// ProxyForPrincipal represents the ProxyForPrincipal field of the request.
	ProxyForPrincipal string `json:"proxy_for_principal"`

	// Expiry represents the Expiry field of the request.
	Expiry int64 `json:"expiry"`
}

// RoleRequest represents the request information to get the role token.
type RoleRequest struct {
	// Domain represents the domain field of the request.
	Domain string `json:"domain"`

	// Role represents the role field of the request.
	Role string `json:"role"`

	// ProxyForPrincipal represents the ProxyForPrincipal field of the request.
	ProxyForPrincipal string `json:"proxy_for_principal"`

	// MinExpiry represents the MinExpiry field of the request.
	MinExpiry int64 `json:"min_expiry"`

	// MaxExpiry represents the MaxExpiry field of the request.
	MaxExpiry int64 `json:"max_expiry"`
}

// AccessResponse represents the AccessTokenResponse from postAccessTokenRequest.
type AccessResponse = service.AccessTokenResponse

// RoleResponse represents the basic information of the role token.
type RoleResponse = service.RoleToken

// NTokenResponse represents the response information of get N-token request.
type NTokenResponse struct {
	// NToken represents the N-token generated.
	NToken string `json:"token"`
}

// SvcCertResponse represents the response information of get svccert request.
type SvcCertResponse struct {
	Cert []byte `json:"cert"`
}

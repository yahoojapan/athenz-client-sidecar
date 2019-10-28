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

// RoleRequest represent the request information to get the role token.
type RoleRequest struct {
	// Domain represent the domain field of the request.
	Domain string `json:"domain"`

	// Role represent the role field of the request.
	Role string `json:"role"`

	// ProxyForPrincipal represent the ProxyForPrincipal field of the request.
	ProxyForPrincipal string `json:"proxy_for_principal"`

	// MinExpiry represent the MinExpiry field of the request.
	MinExpiry int64 `json:"min_expiry"`

	// MaxExpiry represent the MaxExpiry field of the request.
	MaxExpiry int64 `json:"max_expiry"`
}

// RoleResponse represent the basic information of the role token.
type RoleResponse = service.RoleToken

// NTokenResponse represent the response information of get N-token request.
type NTokenResponse struct {
	// NToken represent the N-token generated.
	NToken string `json:"token"`
}

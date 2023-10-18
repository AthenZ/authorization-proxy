// Copyright 2023 LY Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package handler

import (
	"github.com/AthenZ/authorization-proxy/v4/config"
	"github.com/AthenZ/authorization-proxy/v4/service"
)

// Option represents a functional option for gRPC Handler
type GRPCOption func(*GRPCHandler)

var defaultGRPCOptions = []GRPCOption{}

// WithProxyConfig returns a proxy config functional option
func WithProxyConfig(cfg config.Proxy) GRPCOption {
	return func(h *GRPCHandler) {
		h.proxyCfg = cfg
	}
}

// WithRoleTokenConfig returns a role token config functional option
func WithRoleTokenConfig(cfg config.RoleToken) GRPCOption {
	return func(h *GRPCHandler) {
		h.roleCfg = cfg
	}
}

// WithAuthorizationd returns a authorizationd functional option
func WithAuthorizationd(a service.Authorizationd) GRPCOption {
	return func(h *GRPCHandler) {
		h.authorizationd = a
	}
}

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

// PrincipalMock is a mock of Principal
type PrincipalMock struct {
	NameFunc       func() string
	RolesFunc      func() []string
	DomainFunc     func() string
	IssueTimeFunc  func() int64
	ExpiryTimeFunc func() int64
}

// OAuthAccessTokenMock is a mock of OAuthAccessToken
type OAuthAccessTokenMock struct {
	PrincipalMock
	ClientIDFunc func() string
}

// Name is a mock implementation of Principal
func (p *PrincipalMock) Name() string {
	return p.NameFunc()
}

// Roles is a mock implementation of Principal
func (p *PrincipalMock) Roles() []string {
	return p.RolesFunc()
}

// Domain is a mock implementation of Principal
func (p *PrincipalMock) Domain() string {
	return p.DomainFunc()
}

// IssueTime is a mock implementation of Principal
func (p *PrincipalMock) IssueTime() int64 {
	return p.IssueTimeFunc()
}

// ExpiryTime is a mock implementation of Principal
func (p *PrincipalMock) ExpiryTime() int64 {
	return p.ExpiryTimeFunc()
}

// AuthorizedRoles is a mock implementation of Principal
func (p *PrincipalMock) AuthorizedRoles() []string {
	return p.AuthorizedRoles()
}

// ClientID is a mock implementation of OAuthAccessToken
func (oat *OAuthAccessTokenMock) ClientID() string {
	return oat.ClientIDFunc()
}

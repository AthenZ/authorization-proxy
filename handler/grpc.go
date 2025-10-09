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
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"

	authorizerd "github.com/AthenZ/athenz-authorizer/v5"
	"github.com/AthenZ/authorization-proxy/v4/config"
	"github.com/AthenZ/authorization-proxy/v4/service"
	"github.com/kpango/gache/v2"
	"github.com/kpango/glg"
	"github.com/mwitkow/grpc-proxy/proxy"
	"golang.org/x/sync/singleflight"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const gRPC = "grpc"

type GRPCHandler struct {
	proxyCfg       config.Proxy
	roleCfg        config.RoleToken
	atCfg          config.AccessToken
	authorizationd service.Authorizationd
	connMap        gache.Map[string, *grpc.ClientConn]
	group          singleflight.Group
}

func NewGRPC(opts ...GRPCOption) (grpc.StreamHandler, io.Closer) {
	gh := new(GRPCHandler)
	for _, opt := range append(defaultGRPCOptions, opts...) {
		opt(gh)
	}

	if !strings.EqualFold(gh.proxyCfg.Scheme, gRPC) {
		return nil, nil
	}

	if gh.roleCfg.Enable && gh.roleCfg.RoleAuthHeader == "" {
		gh.roleCfg.RoleAuthHeader = "Athenz-Role-Auth"
	}

	if gh.atCfg.Enable && gh.atCfg.AccessTokenAuthHeader == "" {
		gh.atCfg.AccessTokenAuthHeader = "Authorization"
	}

	dialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}

	target := net.JoinHostPort(gh.proxyCfg.Host, strconv.Itoa(int(gh.proxyCfg.Port)))

	return proxy.TransparentHandler(func(ctx context.Context, fullMethodName string) (cctx context.Context, conn grpc.ClientConnInterface, err error) {
		for _, pattern := range gh.proxyCfg.OriginHealthCheckPaths {
			if pattern != "" &&
				(fullMethodName == pattern || wildcardMatch(pattern, fullMethodName)) {
				glg.Infof("Authorization checking skipped on: %s by pattern %s", fullMethodName, pattern)
				conn, err = gh.dialContext(ctx, target, dialOpts...)
				return ctx, conn, err
			}
		}
		p, err := gh.authorize(ctx, fullMethodName)
		if err != nil {
			return ctx, nil, err
		}
		ctx = metadata.AppendToOutgoingContext(ctx,
			"X-Athenz-Principal", p.Name(),
			"X-Athenz-Role", strings.Join(p.Roles(), ","),
			"X-Athenz-Domain", p.Domain(),
			"X-Athenz-Issued-At", strconv.FormatInt(p.IssueTime(), 10),
			"X-Athenz-Expires-At", strconv.FormatInt(p.ExpiryTime(), 10))

		if c, ok := p.(authorizerd.OAuthAccessToken); ok {
			ctx = metadata.AppendToOutgoingContext(ctx, "X-Athenz-Client-ID", c.ClientID())
		}

		conn, err = gh.dialContext(ctx, target, dialOpts...)
		return ctx, conn, err
	}), gh
}

func (gh *GRPCHandler) authorize(ctx context.Context, fullMethodName string) (p authorizerd.Principal, err error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, ErrGRPCMetadataNotFound)
	}
	var rerr error
	p, rerr = gh.authorizeRoleToken(ctx, fullMethodName, md)
	if rerr == nil {
		return p, nil
	}
	var aerr error
	p, aerr = gh.authorizeAccessToken(ctx, fullMethodName, md)
	if aerr != nil {
		return nil, status.Error(codes.Unauthenticated, errors.Join(aerr, rerr).Error())
	}
	return p, nil
}

func (gh *GRPCHandler) authorizeRoleToken(ctx context.Context, fullMethodName string, md metadata.MD) (p authorizerd.Principal, err error) {
	if !gh.roleCfg.Enable {
		return nil, status.Error(codes.Unauthenticated, ErrRoleTokenDisabled)
	}
	rts := md.Get(gh.roleCfg.RoleAuthHeader)
	if len(rts) == 0 {
		return nil, status.Error(codes.Unauthenticated, ErrRoleTokenNotFound)
	}
	p, err = gh.authorizationd.AuthorizeRoleToken(ctx, trimBearer(rts[0]), gRPC, fullMethodName)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	return p, nil
}

func (gh *GRPCHandler) authorizeAccessToken(ctx context.Context, fullMethodName string, md metadata.MD) (p authorizerd.Principal, err error) {
	if !gh.atCfg.Enable {
		return nil, status.Error(codes.Unauthenticated, ErrAccessTokenDisabled)
	}
	ats := md.Get(gh.atCfg.AccessTokenAuthHeader)
	if len(ats) == 0 {
		return nil, status.Error(codes.Unauthenticated, ErrAccessTokenNotFound)
	}
	tok := trimBearer(ats[0])
	cs, ok := clientCertFromContext(ctx)
	if ok && cs != nil && cs[0] != nil {
		p, err = gh.authorizationd.AuthorizeAccessToken(ctx, tok, gRPC, fullMethodName, cs[0])
	} else {
		p, err = gh.authorizationd.AuthorizeAccessToken(ctx, tok, gRPC, fullMethodName, nil)
	}
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	return p, nil
}

func (gh *GRPCHandler) Close() error {
	gh.connMap.Range(func(target string, conn *grpc.ClientConn) bool {
		if conn != nil {
			if err := conn.Close(); err != nil {
				glg.Warnf("failed to close connection. target: %s, err: %v", target, err)
			}
			gh.connMap.Delete(target)
		}
		return true
	})
	return nil
}

func (gh *GRPCHandler) dialContext(ctx context.Context, target string, dialOpts ...grpc.DialOption) (conn *grpc.ClientConn, err error) {
	if conn, ok := gh.connMap.Load(target); ok {
		if isHealthy(conn) {
			return conn, nil
		}
	}

	v, err, _ := gh.group.Do(target, func() (interface{}, error) {
		conn, err := grpc.NewClient(target, dialOpts...)
		if err != nil {
			return nil, err
		}
		gh.connMap.Store(target, conn)
		return conn, nil
	})
	if err == nil {
		if conn, ok := v.(*grpc.ClientConn); ok {
			return conn, nil
		}
	}
	return grpc.NewClient(target, dialOpts...)
}

func clientCertFromContext(ctx context.Context) ([]*x509.Certificate, bool) {
	pr, ok := peer.FromContext(ctx)
	if !ok || pr == nil || pr.AuthInfo == nil {
		return nil, false
	}
	ti, ok := pr.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, false
	}
	state := ti.State
	if len(state.PeerCertificates) == 0 {
		return nil, false
	}
	return state.PeerCertificates, true
}

func isHealthy(conn *grpc.ClientConn) bool {
	glg.Debugf("conn.GetState(): %s", conn.GetState().String())
	switch conn.GetState() {
	case connectivity.Ready, connectivity.Idle, connectivity.Connecting:
		return true
	default:
		return false
	}
}

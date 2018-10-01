package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"ghe.corp.yahoo.co.jp/athenz/athenz-tenant-sidecar/config"
	"github.com/kpango/fastime"
	"github.com/kpango/gache"
	"github.com/pkg/errors"
	"golang.org/x/sync/singleflight"
)

type Role interface {
	StartRoleUpdater(context.Context) Role
	GetRoleProvider() RoleProvider
}

type role struct {
	cfg                   config.Role
	token                 TokenProvider
	athenzURL             string
	athenzPrincipleHeader string
	domainRoleCache       gache.Gache
	group                 singleflight.Group
}

type cacheData struct {
	token             *RoleToken
	domain            string
	role              string
	proxyForPrincipal string
	minExpiry         time.Duration
	maxExpiry         time.Duration
}

type RoleToken struct {
	Token      string `json:"token"`
	ExpiryTime int64  `json:"expiryTime"`
}

type RoleProvider func(context.Context, string, string, string, time.Duration, time.Duration) (*RoleToken, error)

var (
	ErrRoleTokenRequestFailed = errors.New("Failed to fetch RoleToken")
	DefaultExpiry             = time.Minute * 120 // https://github.com/yahoo/athenz/blob/master/utils/zts-roletoken/zts-roletoken.go#L42
)

func NewRoleService(cfg config.Role, token TokenProvider) Role {
	return &role{
		cfg:                   cfg,
		token:                 token,
		athenzURL:             cfg.AthenzURL,
		athenzPrincipleHeader: "Yahoo-Principal-Auth",
		domainRoleCache:       gache.New(),
	}
}

func (r *role) StartRoleUpdater(ctx context.Context) Role {
	r.domainRoleCache.EnableExpiredHook().SetExpiredHook(func(fctx context.Context, key string) {
		domain, role, principal := decode(key)
		r.updateRoleToken(fctx, domain, role, principal, DefaultExpiry, DefaultExpiry)
	}).StartExpired(ctx, DefaultExpiry/5)
	return r
}

func (r *role) GetRoleProvider() RoleProvider {
	return r.getRoleToken
}

func (r *role) getRoleToken(ctx context.Context, domain, role, proxyForPrincipal string, minExpiry, maxExpiry time.Duration) (*RoleToken, error) {
	tok, ok := r.getCache(domain, role, proxyForPrincipal)
	if !ok {
		return r.updateRoleToken(ctx, domain, role, proxyForPrincipal, minExpiry, maxExpiry)
	}
	return tok, nil
}

func (r *role) updateRoleToken(ctx context.Context, domain, role, proxyForPrincipal string, minExpiry, maxExpiry time.Duration) (*RoleToken, error) {

	tok, err, _ := r.group.Do(encode(domain, role, proxyForPrincipal), func() (interface{}, error) {
		u := fmt.Sprintf("%s/domain/%s/token?role=%s",
			r.athenzURL, domain, url.QueryEscape(role))

		switch {
		case minExpiry > 0:
			u += fmt.Sprintf("&minExpiryTime=%d", minExpiry)
			fallthrough
		case maxExpiry > 0:
			u += fmt.Sprintf("&maxExpiryTime=%d", maxExpiry)
			fallthrough
		case proxyForPrincipal != "":
			u += fmt.Sprintf("&proxyForPrincipal=%s", proxyForPrincipal)
		}

		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}

		tok, err := r.token()
		if err != nil {
			return nil, err
		}

		req.Header.Set("Yahoo-Principal-Auth", tok)

		res, err := http.DefaultClient.Do(req.WithContext(ctx))

		if err != nil {
			return nil, err
		}
		defer func() {
			if res != nil {
				io.Copy(ioutil.Discard, res.Body)
				if res.Body != nil {
					res.Body.Close()
				}
			}
		}()

		if res.StatusCode != http.StatusOK {
			return nil, ErrRoleTokenRequestFailed
		}

		var data *RoleToken
		err = json.NewDecoder(res.Body).Decode(&data)
		if err != nil {
			return nil, err
		}

		r.domainRoleCache.SetWithExpire(encode(domain, role, proxyForPrincipal), &cacheData{
			token:             data,
			domain:            domain,
			role:              role,
			proxyForPrincipal: proxyForPrincipal,
			minExpiry:         minExpiry,
			maxExpiry:         maxExpiry,
		}, time.Unix(data.ExpiryTime, 0).Sub(fastime.Now())-time.Minute)
		return data, nil
	})

	if err != nil {
		return nil, err
	}

	return tok.(*RoleToken), nil
}

// TODO domain role 単位でのキャッシュにする
func encode(domain, role, principal string) string {
	return fmt.Sprintf("%s-%s-%s", domain, role, principal)
}

func decode(key string) (string, string, string) {
	keys := strings.SplitN(key, "-", 3)
	if len(keys) < 2 {
		return key, "", ""
	}
	if len(keys) < 3 {
		return keys[0], keys[1], ""
	}
	return keys[0], keys[1], keys[2]
}

func (r *role) getCache(domain, role, principal string) (*RoleToken, bool) {
	val, ok := r.domainRoleCache.Get(encode(domain, role, principal))
	if !ok {
		return nil, false
	}
	return val.(*cacheData).token, ok
}

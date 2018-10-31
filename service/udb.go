package service

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	"ghe.corp.yahoo.co.jp/athenz/athenz-tenant-sidecar/config"
	"github.com/pkg/errors"
)

// UDB represents the interface to get user information from User Database.
type UDB interface {
	GetByGUID(appID, guid string, keys []string) (map[string]string, error)
}

type udb struct {
	hc         CertProvider
	host       string
	httpClient *http.Client
}

// NewUDBClient returns the UDB interface to get user information from User Database.
func NewUDBClient(cfg config.UDB, hc CertProvider) UDB {
	return &udb{
		hc: hc,
		// host: fmt.Sprintf("%s://%s:%d/%s/%s", cfg.Scheme, config.GetActualValue(cfg.Host), cfg.Port, config.GetActualValue(cfg.Version), "users"),
		host:       cfg.URL,
		httpClient: http.DefaultClient,
	}
}

// GetByGUID returns user details from User Database, and any error return from User Database server.
// This function get users data by GUID and return.
func (u *udb) GetByGUID(appID, guid string, keys []string) (map[string]string, error) {
	url := fmt.Sprintf("%s/%s?fields=%s", u.host, guid, strings.Join(keys, ","))
	return u.doRequest(appID, http.MethodGet, url, "", nil)
}

// doRequest returns user details from User Database, or any error return from User Database server.
// This function send a HTTP request to specified UDB url, append the authorization header, decode the result, and return to user.
func (u *udb) doRequest(appID, method, url, cookie string, body io.Reader) (map[string]string, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	cert, err := u.hc(appID)
	if err != nil {
		return nil, err
	}

	// set request headers
	req.Header.Del("Yahoo-App-Auth")
	req.Header.Set("Yahoo-App-Auth", cert)

	req.Header.Del("Content-Type")
	req.Header.Set("Content-Type", "application/json")

	if len(cookie) > 0 {
		req.Header.Del("Cookie")
		req.Header.Set("Cookie", cookie)
	}

	// fire HTTP request
	res, err := u.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() {
		io.Copy(ioutil.Discard, res.Body)
		res.Body.Close()
	}()

	// StatusOK 200 でリクエスト成功
	if res.StatusCode != http.StatusOK {
		return nil, errors.New("Error: response status " + strconv.Itoa(res.StatusCode))
	}

	// decode response body
	var data map[string]string
	err = json.NewDecoder(res.Body).Decode(&data)
	if err != nil {
		return nil, err
	}

	var b []byte
	for k, v := range data {
		b, err = base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, err
		}
		data[k] = string(b[:len(b)])
		b = b[:0]
	}

	return data, nil
}

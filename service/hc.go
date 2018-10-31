package service

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"ghe.corp.yahoo.co.jp/athenz/athenz-tenant-sidecar/config"
	"github.com/kpango/gache"
	"github.com/kpango/glg"
	"github.com/pkg/errors"
)

// HC is the interface for managing and storing host certificates. It can update its certificate automatically and provides a certificate provider for retrieving the latest certificate.
type HC interface {
	// StartCertUpdater starts the internal updater that automatically updates the certificates.
	StartCertUpdater(ctx context.Context)
	// GetCertProvider returns a CertProvider function for retrieving the certificate.
	GetCertProvider() CertProvider
}

// hc is an implementation of HC interface.
type hc struct {
	// certs is a thread-safe cache for the certificates.
	certs gache.Gache
	// ip is the IP address of the target host.
	ip string
	// hostname is the host name of the target host.
	hostname string
	// token is token provider for retrieving the authentication token.
	token TokenProvider
	// athenzURL is the URL of the Athenz server.
	athenzURL string
	// athenzPrincipleHeader is the HTTP header name for putting the authentication token.
	athenzPrincipleHeader string
	// nextExpire indicates when the updater should run again.
	nextExpire time.Duration
	// lastRefreshed indicates when is the last time that the updater has run.
	lastRefreshed time.Time
	// certExpire is the certificate updating period if all certificates do not have expiry times or no certificates returned.
	certExpire time.Duration
	// certExpireMargin is the buffer time for using the certificate. The updater will run earlier by this duration before the expiration so that the certificate can still have a reasonable time frame for using.
	certExpireMargin time.Duration
	// httpClient is the HTTP client to perform HTTP request
	httpClient *http.Client
	// updater is to perform the update action
	updater updater
}

// updater is the interface to update the internally status
type updater interface {
	update() error
}

// certificate is the response from server. It contains an app ID and the value of the certificate.
type certificate struct {
	AppID string `xml:"appid,attr"`
	Cert  string `xml:",chardata"`
}

// certificates is the response from server. It contains list of certificates of a specific host.
type certificates struct {
	Hostname     string        `xml:"hostname,attr"`
	Certificates []certificate `xml:"certificate"`
}

// CertProvider is a function that can return a certificate.
type CertProvider func(string) (string, error)

const (
	// zts is zts URL.
	zts = "zts.athenz.yahoo.co.jp:4443/wsca/v1"
	// defaultCertExpireTime is the default certificate expiry time.
	defaultCertExpireTime = 30 * time.Minute
	// defaultCertExpireMargin is the default certificate expiry margin.
	defaultCertExpireMargin = time.Minute
	// maxExpiryDuration is the assumed limit of the certificate expiry time (1 year). Affects update period.
	maxExpiryDuration = 365 * 24 * time.Hour
)

var (
	// ErrCertNotFound is returned by CertProvider when no certificates can be found.
	ErrCertNotFound = errors.New("certification not found")
)

// NewHC creates an object implementing HC. The object works based on the given config.HC and get authentication token from the given TokenProvider. Default values will be used if the configuration contains invalid values.
func NewHC(cfg config.HC, prov TokenProvider) (HC, error) {
	// valid CertExpire
	exp, err := time.ParseDuration(cfg.CertExpire)
	if err != nil {
		glg.Warn(err)
		exp = defaultCertExpireTime
	}
	if exp > maxExpiryDuration {
		exp = maxExpiryDuration
	}

	// valid CertExpireMargin
	m, err := time.ParseDuration(cfg.CertExpireMargin)
	if err != nil {
		glg.Warn(err)
		m = defaultCertExpireMargin
	}

	h := &hc{
		certs:                 gache.New(),
		ip:                    config.GetValue(cfg.IP),
		hostname:              config.GetValue(cfg.Hostname),
		token:                 prov,
		athenzURL:             cfg.AthenzURL,
		athenzPrincipleHeader: cfg.AuthHeader,
		lastRefreshed:         time.Now(),
		certExpire:            exp,
		certExpireMargin:      m,

		// use zero value, set after 1st update
		// nextExpire:            defaultCertExpireTime,
	}
	// internal fields
	h.httpClient = http.DefaultClient
	h.updater = h

	return h, nil
}

// GetCertProvider returns the internal CertProvider function for retrieving the certificate
func (h *hc) GetCertProvider() CertProvider {
	return h.getCertificate
}

// getCertificate returns the certificate of the given app ID. If not found, returns ErrCertNotFound.
func (h *hc) getCertificate(appID string) (string, error) {
	cert, ok := h.certs.Get(appID)
	if !ok {
		return "", ErrCertNotFound
	}

	return cert.(string), nil
}

// update updates the internal certificate cache to keep in sync. with the server side.
func (h *hc) update() error {

	// 1. get authentication token
	token, err := h.token()
	if err != nil {
		return err
	}

	// 2. get latest certificates from server
	// d = expire duration (unit = second, hard-code to 1 hour only currently)
	// P.S. IP may be IPv6
	u := fmt.Sprintf("https://%s/containercerts/mh/%s?d=%d&ip=%s", h.athenzURL, h.hostname, time.Hour/time.Second, url.QueryEscape(h.ip))
	certs, err := getCertificatesByHttp(h.httpClient, u, h.athenzPrincipleHeader, token)
	if err != nil {
		return err
	}

	// 3. find earliest expiry time & store the certificates
	maxExpiry := time.Now().Add(maxExpiryDuration)
	earliestExpiry := maxExpiry

	for _, cert := range certs.Certificates {
		exp, err := checkExpire(cert.Cert)
		if err != nil {
			glg.Warn(err)
			continue
		}
		if exp.Before(earliestExpiry) {
			earliestExpiry = exp
		}
		h.certs.SetWithExpire(cert.AppID, cert.Cert, exp.Sub(time.Now()))
	}

	// 4. set next update time
	if earliestExpiry != maxExpiry {
		h.nextExpire = earliestExpiry.Sub(time.Now())
	} else {
		// certExpire <= maxExpiry (refer to NewHC)
		h.nextExpire = h.certExpire
	}

	// 5. record this update time
	h.lastRefreshed = time.Now()

	return nil
}

// getCertificatesByHttp makes the HTTP request to server and parse its response.
func getCertificatesByHttp(client *http.Client, targetUrl string, tokenHeader string, token string) (certs *certificates, err error) {

	// 1. create HTTP request
	req, err := http.NewRequest(http.MethodGet, targetUrl, nil)
	if err != nil {
		return nil, err
	}

	// 2. prepare header
	req.Header.Set(tokenHeader, token)

	// 3. do request
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	// bind current error value, prevent closure
	defer func(err error) {
		// godoc: The request Body, if non-nil, will be closed by the underlying Transport, even on errors.
		// no needs to care request body

		// godoc: On error, any Response can be ignored. A non-nil Response with a non-nil error only occurs when CheckRedirect fails, and even then the returned Response.Body is already closed.
		// close only if error is nil
		if res.Body != nil && err == nil {
			closeErr := flushAndClose(res.Body)
			if closeErr != nil {
				// ignore error, log only
				glg.Error(closeErr)
			}
		}
	}(err)

	// 4. validate response
	if res.StatusCode != http.StatusOK {
		err = fmt.Errorf("GET %s returned status code %d", targetUrl, res.StatusCode)
		return nil, err
	}

	// 5. decode response
	var _certs certificates
	certs = &_certs
	err = xml.NewDecoder(res.Body).Decode(&certs)
	if err != nil {
		return nil, err
	}

	return certs, nil
}

// flushAndClose helps to close a HTTP.Response.Body. Please ensure the response body is non-nil.
func flushAndClose(rc io.ReadCloser) error {
	// flush
	_, err := io.Copy(ioutil.Discard, rc)
	if err != nil {
		return err
	}
	// close
	return rc.Close()
}

// checkExpire returns the expiry timestamp of the given certificate.
func checkExpire(cert string) (time.Time, error) {
	for _, part := range strings.Split(cert, ";") {
		if strings.HasPrefix(part, "t=") {
			v, err := strconv.ParseInt(strings.TrimPrefix(part, "t="), 10, 64)
			if err != nil {
				return time.Time{}, err
			}
			return time.Unix(v, 0), nil
		}
	}
	return time.Time{}, nil
}

// StartCertUpdater starts the automatic certificate updater. Update period depends on certificates' expiry times and the configuration. On error, run again in next second.
func (h *hc) StartCertUpdater(ctx context.Context) {

	// start auto expiry
	h.certs.StartExpired(ctx, time.Second*30)

	go func() {
		var err error
		err = h.updater.update()
		if err != nil {
			glg.Error(err)
		}

		tick := time.NewTicker(time.Second)
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				err = h.updater.update()
				tick.Stop()
				if err != nil {
					glg.Error(err)
					tick = time.NewTicker(time.Second)
				} else {
					// run earlier by the margin time so that the certificate can still have reasonable time frame for using
					tick = time.NewTicker(h.nextExpire - h.certExpireMargin)
				}
			}
		}
	}()
}

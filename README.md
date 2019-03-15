# Athenz Client Sidecar for Kubernetes

[![License: Apache](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square)](https://opensource.org/licenses/Apache-2.0) [![release](https://img.shields.io/github/release/yahoojapan/athenz-client-sidecar.svg?style=flat-square)](https://github.com/yahoojapan/athenz-client-sidecar/releases/latest) [![CircleCI](https://circleci.com/gh/yahoojapan/athenz-client-sidecar.svg)](https://circleci.com/gh/yahoojapan/athenz-client-sidecar) [![codecov](https://codecov.io/gh/yahoojapan/athenz-client-sidecar/branch/master/graph/badge.svg?token=2CzooNJtUu&style=flat-square)](https://codecov.io/gh/yahoojapan/athenz-client-sidecar) [![Go Report Card](https://goreportcard.com/badge/github.com/yahoojapan/athenz-client-sidecar)](https://goreportcard.com/report/github.com/yahoojapan/athenz-client-sidecar) [![GolangCI](https://golangci.com/badges/github.com/yahoojapan/athenz-client-sidecar.svg?style=flat-square)](https://golangci.com/r/github.com/yahoojapan/athenz-client-sidecar) [![Codacy Badge](https://api.codacy.com/project/badge/Grade/32397d339f6c450a82af72c8a0c15e5f)](https://www.codacy.com/app/i.can.feel.gravity/athenz-client-sidecar?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=yahoojapan/athenz-client-sidecar&amp;utm_campaign=Badge_Grade) [![GoDoc](http://godoc.org/github.com/yahoojapan/athenz-client-sidecar?status.svg)](http://godoc.org/github.com/yahoojapan/athenz-client-sidecar) [![DepShield Badge](https://depshield.sonatype.org/badges/yahoojapan/athenz-client-sidecar/depshield.svg)](https://depshield.github.io)


Table of Contents
=================

- [Athenz Client Sidecar for Kubernetes](#athenz-client-sidecar-for-kubernetes)
  - [What is Athenz client sidecar?](#what-is-athenz-client-sidecar)
    - [Get Athenz N-Token from client sidecar](#get-athenz-n-token-from-client-sidecar)
    - [Get Athenz Role Token from client sidecar](#get-athenz-role-token-from-client-sidecar)
    - [Proxy HTTP request (add corresponding Athenz authorization token)](#proxy-http-request-add-corresponding-athenz-authorization-token)
  - [Use Case](#use-case)
  - [Specification](#specification)
    - [Get N-token from Athenz through client sidecar](#get-n-token-from-athenz-through-client-sidecar)
    - [Get role token from Athenz through client sidecar](#get-role-token-from-athenz-through-client-sidecar)
    - [Proxy requests and append N-token authentication header](#proxy-requests-and-append-n-token-authentication-header)
    - [Proxy requests and append role token authentication header](#proxy-requests-and-append-role-token-authentication-header)
  - [Configuration](#configuration)
  - [Developer Guide](#developer-guide)
    - [Example code](#example-code)
      - [Get N-token from client sidecar](#get-n-token-from-client-sidecar)
      - [Get role token from client sidecar](#get-role-token-from-client-sidecar)
      - [Proxy request through client sidecar (append N-token)](#proxy-request-through-client-sidecar-append-n-token)
      - [Proxy request through client sidecar (append role token)](#proxy-request-through-client-sidecar-append-role-token)
  - [Deployment Procedure](#deployment-procedure)

## What is Athenz client sidecar?

Athenz client sidecar is an implementation of [Kubernetes sidecar container](https://kubernetes.io/blog/2015/06/the-distributed-system-toolkit-patterns/) to provide a common interface to retrieve authentication and authorization credential from Athenz server.

### Get Athenz N-Token from client sidecar

![Sidecar architecture (get N-token)](./doc/assets/client_sidecar_arch_n_token.png)

Whenever user wants to get the N-token, user does not need to focus on extra logic to generate token, user can access client sidecar container instead of implementing the logic themselves, to avoid the extra logic implemented by user.
For instance, the client sidecar container caches the token and periodically generates the token automatically. For user this logic is transparent, but it improves the overall performance as it does not generate the token every time whenever the user asks for it.

### Get Athenz Role Token from client sidecar

![Sidecar architecture (get Role token)](./doc/assets/client_sidecar_arch_z_token.png)

User can get the role token from the client sidecar container. Whenever user requests for the role token, the sidecar process will get the role token from Athenz if it is not in the cache, and cache it in memory. The background thread will update corresponding role token periodically.

### Proxy HTTP request (add corresponding Athenz authorization token)

![Sidecar architecture (proxy request)](./doc/assets/client_sidecar_arch_proxy.png)

User can also use the reverse proxy endpoint to proxy the request to another server that supports Athenz token validation. The proxy endpoint will append the necessary authorization (N-token or role token) HTTP header to the request and proxy the request to the destination server. User does not need to care about the token generation logic where this sidecar container will handle it, also it supports similar caching mechanism with the N-token usage.

---

## Use Case

1. `GET /ntoken`
   - Get service token from Athenz
1. `POST /roletoken`
   - Get role token from Athenz
1. `/proxy/ntoken`
   - Append service token to the request header, and send the request to proxy destination
1. `/proxy/roletoken`
   - Append role token to the request header, and send the request to proxy destination

---

## Specification

### Get N-token from Athenz through client sidecar

- Only Accept HTTP GET request.
- Response body contains below information in JSON format.

| Name    | Description           | Example                                                                                            |
| ------- | --------------------- | -------------------------------------------------------------------------------------------------- |
| token | The n-token generated | v=S1;d=client;n=service;h=localhost;a=6996e6fc49915494;t=1486004464;e=1486008064;k=0;s=[signeture] |

  Example:

``` json
{
  "token": "v=S1;d=client;n=service;h=localhost;a=6996e6fc49915494;t=1486004464;e=1486008064;k=0;s=[signeture]"
}
```

### Get role token from Athenz through client sidecar

- Only accept HTTP POST request.
- Request body must contains below information in JSON format.

| Name                | Description                                                 | Required? | Example           |
| ------------------- | ----------------------------------------------------------- | --------- | ----------------- |
| domain              | Role token domain name                                      | Yes       | domain.shopping   |
| role                | Role token role name                                        | Yes       | users             |
| proxy_for_principal | Role token proxyForPrincipal name                           | No        | proxyForPrincipal |
| min_expiry          | Role token minimal expiry time (in second)                  | No        | 100               |
| max_expiry          | Role token maximum expiry time (in second), Default is 7200 | No        | 1000              |

Example:

``` json
{
  "domain": "domain.shopping",
  "role": "users",
  "proxy_for_principal": "proxyForPrincipal",
  "minExpiry": 100,
  "maxExpiry": 1000
}
```

- Response body contains below information in JSON format.

| Name       | Description                       | Example                                                                                                                                                |
| ---------- | --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| token      | The role token generated          | v=Z1;d=domain.shopping;r=users;p=domain.travel.travel-site;h=athenz.co.jp;a=9109ee08b79e6b63;t=1528853625;e=1528860825;k=0;i=192.168.1.1;s=[signature] |
| expiryTime | The expiry time of the role token | 1528860825                                                                                                                                             |

Example:

``` json
{
  "token": "v=Z1;d=domain.shopping;r=users;p=domain.travel.travel-site;h=athenz.co.jp;a=9109ee08b79e6b63;t=1528853625;e=1528860825;k=0;i=192.168.1.1;s=s9WwmhDeO_En3dvAKvh7OKoUserfqJ0LT5Pct5Gfw5lKNKGH4vgsHLI1t0JFSQJWA1ij9ay_vWw1eKaiESfNJQOKPjAANdFZlcXqCCRUCuyAKlbX6KmWtQ9JaKSkCS8a6ReOuAmCToSqHf3STdKYF2tv1ZN17ic4se4VmT5aTig-",
  "expiryTime": 1528860825
}
```

### Proxy requests and append N-token authentication header

- Accept any HTTP request.
- Athenz client sidecar will proxy the request and append the n-token to the request header.
- The destination server will return back to user via proxy.

### Proxy requests and append role token authentication header

- Accept any HTTP request.
- Request header must contains below information.

| Name                        | Description                                                  | Required? | Example  |
| --------------------------- | ------------------------------------------------------------ | --------- | -------- |
| Athenz-Role            | The user role name used to generate the role token           | Yes       | users    |
| Athenz-Domain          | The domain name used to generate the role token              | Yes       | provider |
| Athenz-Proxy-Principal | The proxy for principal name used to generate the role token | Yes       | username |

HTTP header Example:

``` none
Athenz-Role: users
Athenz-Domain: provider
Athenz-Proxy-Principal: username
```

- The destination server will return back to user via proxy.

## Configuration

- [config.go](./config/config.go)

## Developer Guide

After injecting client sidecar to user application, user application can access the client sidecar to get authorization and authentication credential from Athenz server. The client sidecar can only access by the user application injected, other application cannot access to the client sidecar. User can access client sidecar by using HTTP request.

### Example code

#### Get N-token from client sidecar

```go
import (
    "encoding/json"
    "fmt"
    "net/http"

    "github.com/yahoojapan/athenz-client-sidecar/model"
)

const scURL = "127.0.0.1" // sidecar URL
const scPort = "8081"

type NTokenResponse = model.NTokenResponse

func GetNToken(appID, nCookie, tCookie, keyID, keyData string, keys []string) (*NTokenResponse, error) {
    url := fmt.Sprintf("http://%s:%s/ntoken", scURL, scPort)

    // make request
    res, err := http.Get(url)
    if err != nil {
        return nil, err
    }
    defer res.Body.Close()

    // validate response
    if res.StatusCode != http.StatusOK {
        err = fmt.Errorf("%s returned status code %d", url, res.StatusCode)
        return nil, err
    }

    // decode request
    var data NTokenResponse
    err = json.NewDecoder(res.Body).Decode(&data)
    if err != nil {
        return nil, err
    }

    return &data, nil
}
```

#### Get role token from client sidecar

```go
import (
    "bytes"
    "encoding/json"
    "fmt"
    "net/http"
    "time"

    "github.com/yahoojapan/athenz-client-sidecar/model"
)

const scURL = "127.0.0.1" // sidecar URL
const scPort = "8081"

type RoleRequest = model.RoleRequest
type RoleResponse = model.RoleResponse

func GetRoleToken(domain, role, proxyForPrincipal string, minExpiry, maxExpiry time.Duration) (*RoleResponse, error) {
    url := fmt.Sprintf("http://%s:%s/roletoken", scURL, scPort)

    r := &RoleRequest{
        Domain:            domain,
        Role:              role,
        ProxyForPrincipal: proxyForPrincipal,
        MinExpiry:         minExpiry,
        MaxExpiry:         maxExpiry,
    }
    reqJSON, _ := json.Marshal(r)

    // create POST request
    req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(reqJSON))
    if err != nil {
        return nil, err
    }
    req.Header.Set("Content-Type", "application/json")

    // make request
    res, err := http.DefaultClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer res.Body.Close()

    // validate response
    if res.StatusCode != http.StatusOK {
        err = fmt.Errorf("%s returned status code %d", url, res.StatusCode)
        return nil, err
    }

    // decode request
    var data RoleResponse
    err = json.NewDecoder(res.Body).Decode(&data)
    if err != nil {
        return nil, err
    }

    return &data, nil
}
```

#### Proxy request through client sidecar (append N-token)

```go
const (
    scURL  = "127.0.0.1" // sidecar URL
    scPort = "8081"
)

var (
    httpClient *http.Client // the HTTP client that use the proxy to append N-token header

    // proxy URL
    proxyNTokenURL    = fmt.Sprintf("http://%s:%s/proxy/ntoken", scURL, scPort)
)

func initHTTPClient() error {
    proxyURL, err := url.Parse(proxyNTokenURL)
    if err != nil {
        return err
    }

    // transport that use the proxy, and append to the client
    transport := &http.Transport{
        Proxy: http.ProxyURL(proxyURL),
    }
    httpClient = &http.Client{
        Transport: transport,
    }

    return nil
}

func MakeRequestUsingProxy(method, targetURL string, body io.Reader) (*[]byte, error) {
    // create POST request
    req, err := http.NewRequest(method, targetURL, body)
    if err != nil {
        return nil, err
    }

    // make request through the proxy
    res, err := httpClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer res.Body.Close()

    // validate response
    if res.StatusCode != http.StatusOK {
        err = fmt.Errorf("%s returned status code %d", targetURL, res.StatusCode)
        return nil, err
    }

    // process response
    data, err := ioutil.ReadAll(res.Body)
    if err != nil {
        return nil, err
    }

    return &data, nil
}
```

#### Proxy request through client sidecar (append role token)

```go
const (
    scURL  = "127.0.0.1" // sidecar URL
    scPort = "8081"
)

var (
    httpClient *http.Client // the HTTP client that use the proxy to append role token header

    // proxy URL
    proxyRoleTokenURL = fmt.Sprintf("http://%s:%s/proxy/roletoken", scURL, scPort)
)

func initHTTPClient() error {
    proxyURL, err := url.Parse(proxyRoleTokenURL)
    if err != nil {
        return err
    }

    // transport that use the proxy, and append to the client
    transport := &http.Transport{
        Proxy: http.ProxyURL(proxyURL),
    }
    httpClient = &http.Client{
        Transport: transport,
    }

    return nil
}

func MakeRequestUsingProxy(method, targetURL string, body io.Reader, role, domain, proxyPrincipal string) (*[]byte, error) {
    // create POST request
    req, err := http.NewRequest(method, targetURL, body)
    if err != nil {
        return nil, err
    }

    // append header for the proxy
    req.Header.Set("Athenz-Role", role)
    req.Header.Set("Athenz-Domain", domain)
    req.Header.Set("Athenz-Proxy-Principal", proxyPrincipal)

    // make request through the proxy
    res, err := httpClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer res.Body.Close()

    // validate response
    if res.StatusCode != http.StatusOK {
        err = fmt.Errorf("%s returned status code %d", targetURL, res.StatusCode)
        return nil, err
    }

    // process response
    data, err := ioutil.ReadAll(res.Body)
    if err != nil {
        return nil, err
    }

    return &data, nil
}
```

We only provided golang example, but user can implement a client using any other language and connect to sidecar container using HTTP request.

## Deployment Procedure

1. Inject client sidecar to your K8s deployment file.

2. Deploy to K8s.

   ```bash
   kubectl apply -f injected_deployments.yaml
   ```

3. Verify if the application running

   ```bash
   # list all the pods
   kubectl get pods -n <namespace>
   # if you are not sure which namespace your application deployed, use `--all-namespaces` option
   kubectl get pods --all-namespaces
  
   # describe the pod to show detail information
   kubectl describe pods <pod_name>
  
   # check application logs
   kubectl logs <pod_name> -c <container_name>
   # e.g. to show client sidecar logs
   kubectl logs nginx-deployment-6cc8764f9c-5c6hm -c athenz-client-sidecar
   ```

## License

```markdown
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
```

## Contributor License Agreement

This project requires contributors to agree to a [Contributor License Agreement (CLA)](https://gist.github.com/ydnjp/3095832f100d5c3d2592).

Note that only for contributions to the garm repository on the [GitHub](https://github.com/yahoojapan/garm), the contributors of them shall be deemed to have agreed to the CLA without individual written agreements.

## Authors

- [kpango](https://github.com/kpango)
- [kevindiu](https://github.com/kevindiu)
- [TakuyaMatsu](https://github.com/TakuyaMatsu)
- [tatyano](https://github.com/tatyano)
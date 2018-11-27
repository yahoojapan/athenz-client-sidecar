# Athenz Tenant Sidecar for Kubernetes

---

## What is Athenz tenant sidecar?

Athenz tenant sidecar is an implementation of [Kubernetes sidecar container](https://kubernetes.io/blog/2015/06/the-distributed-system-toolkit-patterns/) to provide a common interface to retrieve authentication and authorization credential from Athenz server.

### Get Athenz N-Token from tenant sidecar

![Sidecar architecture (get N-token)](./doc/assets/tenant_sidecar_arch_n_token.png)

Whenever user wants to get the N-token, user does not need to focus on extra logic to generate token, user can access tenant sidecar container instead of implementing the logic themselves, to avoid the extra logic implemented by user.
For instance, the tenant sidecar container caches the token and periodically generates the token automatically. For user this logic is transparent, but it improves the overall performance as it does not generate the token every time whenever the user asks for it.

### Get Athenz Role Token from tenant sidecar

![Sidecar architecture (get Role token)](./doc/assets/tenant_sidecar_arch_z_token.png)

User can get the role token from the tenant sidecar container. Whenever user requests for the role token, the sidecar process will get the role token from Athenz if it is not in the cache, and cache it in memory. The background thread will update corresponding role token periodically.

### Proxy HTTP request (add corresponding Athenz authorization token)

![Sidecar architecture (proxy request)](./doc/assets/tenant_sidecar_arch_proxy.png)

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

### 1. Get n-token from Athenz through tenant sidecar

- Only Accept HTTP GET request.
- Response body contains below information in JSON format.

| Name         | Description                       | Example |
|--------------|-----------------------------------|---------|
| n_token      | The n-token generated             | v=S1;d=tenant;n=service;h=localhost;a=6996e6fc49915494;t=1486004464;e=1486008064;k=0;s=[signeture] |

  Example:

``` json
{
  "n_token": "v=S1;d=tenant;n=service;h=localhost;a=6996e6fc49915494;t=1486004464;e=1486008064;k=0;s=[signeture]"
}
```

### 2. Get role token from Athenz through tenant sidecar

- Only accept HTTP POST request.
- Request body must contains below information in JSON format.

| Name                | Description                                                 | Required? | Example           |
|---------------------|-------------------------------------------------------------|-----------|-------------------|
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

| Name       | Description                       | Example    |
|------------|-----------------------------------|------------|
| token      | The role token generated          | v=Z1;d=domain.shopping;r=users;p=domain.travel.travel-site;h=athenz.co.jp;a=9109ee08b79e6b63;t=1528853625;e=1528860825;k=0;i=192.168.1.1;s=[signature] |
| expiryTime | The expiry time of the role token | 1528860825 |

Example:

``` json
{
  "token": "v=Z1;d=domain.shopping;r=users;p=domain.travel.travel-site;h=athenz.co.jp;a=9109ee08b79e6b63;t=1528853625;e=1528860825;k=0;i=192.168.1.1;s=s9WwmhDeO_En3dvAKvh7OKoUserfqJ0LT5Pct5Gfw5lKNKGH4vgsHLI1t0JFSQJWA1ij9ay_vWw1eKaiESfNJQOKPjAANdFZlcXqCCRUCuyAKlbX6KmWtQ9JaKSkCS8a6ReOuAmCToSqHf3STdKYF2tv1ZN17ic4se4VmT5aTig-",
  "expiryTime": 1528860825
}
```

### 3. Proxy requests and append n-token authentication header

- Accept any HTTP request.
- Athenz tenant sidecar will proxy the request and append the n-token to the request header.
- The destination server will return back to user via proxy.

### 4. Proxy requests and append role token authentication header

- Accept any HTTP request.
- Request header must contains below information.

| Name                        | Description                                                  | Required? | Example |
|-----------------------------|--------------------------------------------------------------|-----------|---------|
| Athenz-Role-Auth            | The user role name used to generate the role token           | Yes       |         |
| Athenz-Domain-Auth          | The domain name used to generate the role token              | Yes       |         |
| Athenz-Proxy-Principal-Auth | The proxy for principal name used to generate the role token | Yes       |         |

HTTP header Example:

``` none
Athenz-Role-Auth:
Athenz-Domain-Auth:
Athenz-Proxy-Principal-Auth:
```

- The destination server will return back to user via proxy.

### Configuration

- [config.go](./config/config.go)
- [config details](./doc/config-detail.md)

### Developer Guide

After injecting tenant sidecar to user application, user application can access the tenant sidecar to get authorization and authentication credential from Athenz server. The tenant sidecar can only access by the user application injected, other application cannot access to the tenant sidecar. User can access tenant sidecar by using HTTP request.

#### Example code

```java
public static void main(String[] args) {
  
}
```

### Deployment Procedure

1. Prepare deployment file for K8s.
   Refer to [injector guideline](http://).

1. Deploy to K8s.

   ```bash
   kubectl apply -f injected_deployments.yaml
   ```

1. Verify if the application running

   ```bash
   # list all the pods
   kubectl get pods -n <namespace>
   # if you are not sure which namespace your application deployed, use `--all-namespaces` option
   kubectl get pods --all-namespaces
  
   # describe the pod to show detail information
   kubectl describe pods <pod_name>
  
   # check application logs
   kubectl logs <pod_name> -c <container_name>
   # e.g. to show tenant sidecar logs
   kubectl logs nginx-deployment-6cc8764f9c-5c6hm -c athenz-tenant-sidecar
   ```
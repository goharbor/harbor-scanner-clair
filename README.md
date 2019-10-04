[![Build Status][ci-img]][ci]
[![Coverage Status][cov-img]][cov]

# harbor-scanner-clair

This is a POC of an out-of-tree implementation of the Harbor Scanner Adapter API for [Clair][clair-url].
See https://github.com/goharbor/community/pull/90 for more details.

## TOC

* [Configuration](#configuration)
* [Deploy to minikube](#deploy-to-minikube)

## Configuration

| Name | Default Value | Description |
|------|---------------|-------------|
| `SCANNER_LOG_LEVEL`                | `info` | The log level of `trace`, `debug`, `info`, `warn`, `warning`, `error`, `fatal` or `panic`. The standard logger logs entries with that level or anything above it. |
| `SCANNER_API_SERVER_ADDR`          | `:8080` | Binding address for the API HTTP server. |
| `SCANNER_API_SERVER_READ_TIMEOUT`  | `15s` | The maximum duration for reading the entire request, including the body. |
| `SCANNER_API_SERVER_WRITE_TIMEOUT` | `15s` | The maximum duration before timing out writes of the response. |
| `SCANNER_CLAIR_URL`                | `http://harbor-harbor-clair:6060` | Clair URL |

## Deploy to minikube

1. Configure Docker client with Docker Engine in minikube:
   ```
   eval $(minikube docker-env -p harbor)
   ```
2. Build Docker container:
   ```
   make container
   ```
3. Create `harbor-scanner-clair` deployment and service:
   ```
   kubectl apply -f kube/harbor-scanner-clair.yaml
   ```
4. If everything is fine you should be able to get scanner's metadata:
   ```
   kubectl port-forward service/harbor-scanner-clair 8080:8080 &> /dev/null &
   curl -v http://localhost:8080/api/v1/metadata | jq
   ```

If everything is fine the API will be mounted at [http://localhost:8080/api/v1](http://localhost:8080/api/v1).

[ci-img]: https://travis-ci.org/danielpacak/harbor-scanner-clair.svg?branch=master
[ci]: https://travis-ci.org/danielpacak/harbor-scanner-clair

[cov-img]: https://codecov.io/github/danielpacak/harbor-scanner-clair/branch/master/graph/badge.svg
[cov]: https://codecov.io/github/danielpacak/harbor-scanner-clair

[clair-url]: https://github.com/coreos/clair

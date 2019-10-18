[![GitHub release][release-img]][release]
[![Build Status][ci-img]][ci]
[![Coverage Status][cov-img]][cov]
[![Go Report Card][report-card-img]][report-card]
[![License][license-img]][license]

# Harbor Scanner Adapter for Clair

The Harbor Scanner Adapter for [Clair][clair-url] is a service that translates the Harbor scanning API into Clair API calls
and allows Harbor to use Clair for providing vulnerability reports on images stored in Harbor registry as part of its
vulnerability scan feature.

> See [Proposal: Pluggable Image Vulnerability Scanning][image-vulnerability-scanning-proposal] for more details.

## TOC

* [Configuration](#configuration)
* [Deploy to minikube](#deploy-to-minikube)

## Configuration

Configuration of the adapter is done via environment variables at startup.

| Name | Default Value | Description |
|------|---------------|-------------|
| `SCANNER_LOG_LEVEL`                | `info` | The log level of `trace`, `debug`, `info`, `warn`, `warning`, `error`, `fatal` or `panic`. The standard logger logs entries with that level or anything above it. |
| `SCANNER_API_SERVER_ADDR`          | `:8080` | Binding address for the API HTTP server. |
| `SCANNER_API_SERVER_TLS_CERTIFICATE` | | The absolute path to the x509 certificate file. |
| `SCANNER_API_SERVER_TLS_KEY`         | | The absolute path to the x509 private key file. |
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
3. Configure adapter to handle TLS traffic:
   1. Generate certificate and private key files:
      ```
      $ openssl genrsa -out tls.key 2048
      $ openssl req -new -x509 \
        -key tls.key \
        -out tls.crt \
        -days 365 \
        -subj /CN=harbor-scanner-trivy
      ```
   2. Create a `tls` secret from the two generated files:
      ```
      $ kubectl create secret tls harbor-scanner-clair-tls \
        --cert=tls.crt \
        --key=tls.key
      ```
4. Create `harbor-scanner-clair` deployment and service:
   ```
   kubectl apply -f kube/harbor-scanner-clair.yaml
   ```
5. If everything is fine you should be able to get scanner's metadata:
   ```
   kubectl port-forward service/harbor-scanner-clair 8443:8443 &> /dev/null &
   curl -v https://localhost:8443/api/v1/metadata | jq
   ```

If everything is fine the API will be mounted at [https://localhost:8443/api/v1](https://localhost:8443/api/v1).

[release-img]: https://img.shields.io/github/release/danielpacak/harbor-scanner-clair.svg
[release]: https://github.com/aquasecurity/harbor-scanner-clair/releases
[ci-img]: https://travis-ci.org/danielpacak/harbor-scanner-clair.svg?branch=master
[ci]: https://travis-ci.org/danielpacak/harbor-scanner-clair
[cov-img]: https://codecov.io/github/danielpacak/harbor-scanner-clair/branch/master/graph/badge.svg
[cov]: https://codecov.io/github/danielpacak/harbor-scanner-clair
[report-card-img]: https://goreportcard.com/badge/github.com/danielpacak/harbor-scanner-clair
[report-card]: https://goreportcard.com/report/github.com/danielpacak/harbor-scanner-clair
[license-img]: https://img.shields.io/github/license/danielpacak/harbor-scanner-clair.svg
[license]: https://github.com/aquasecurity/harbor-scanner-clair/blob/master/LICENSE

[clair-url]: https://github.com/coreos/clair
[image-vulnerability-scanning-proposal]: https://github.com/goharbor/community/blob/master/proposals/pluggable-image-vulnerability-scanning_proposal.md

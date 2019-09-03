# harbor-scanner-clair

This is a POC of an out-of-tree implementation of the Harbor Scanner Adapter API for [Clair](https://github.com/coreos/clair).
See https://github.com/goharbor/community/pull/90 for more details.

## TOC

* [Configuration](#configuration)
* [Deploy to minikube](#deploy-to-minikube)
* [Run with Docker](#run-with-docker)

## Configuration

| Name                | Default Value            | Description |
|---------------------|--------------------------|-------------|
| `SCANNER_API_ADDR`  | `:8080`                  | Binding address for the API HTTP server. |
| `SCANNER_CLAIR_URL` | `http://harbor-harbor-clair:6060` | Clair URL |

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

## Run with Docker

```
$ make container-run
```

If everything is fine the API will be mounted at [http://localhost:8080/api/v1](http://localhost:8080/api/v1).

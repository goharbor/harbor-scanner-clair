# harbor-scanner-clair

This is a POC of an out-of-tree implementation of the Harbor Scanner Adapter API for [Clair](https://github.com/coreos/clair).
See https://github.com/goharbor/community/pull/90 for more details.

## Deploy to minikube

```
$ eval $(minikube docker-env -p harbor)
$ make container
$ kubectl -n harbor apply -f kube/harbor-scanner-clair.yaml
$ kubectl -n harbor port-forward service/harbor-scanner-clair 8080:8080 &> /dev/null &
```

If everything is fine the API will be mounted at [http://localhost:8080/api/v1](http://localhost:8080/api/v1).

## Run with Docker

```
$ make container-run
```

If everything is fine the API will be mounted at [http://localhost:8080/api/v1](http://localhost:8080/api/v1).

# harbor-clair-adapter

```
$ eval $(minikube docker-env -p harbor)
$ make container
$ kubectl -n harbor apply -f kube/harbor-clair-adapter.yaml
```

## TODO

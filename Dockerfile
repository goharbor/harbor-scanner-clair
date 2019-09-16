FROM scratch

ADD bin/harbor-scanner-clair /harbor-scanner-clair

ENTRYPOINT ["/harbor-scanner-clair"]

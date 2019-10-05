FROM scratch

ADD scanner-clair /scanner-clair

ENTRYPOINT ["/harbor-scanner-clair"]

FROM scratch

ADD bin/scanner-clair /app/scanner-clair

ENTRYPOINT ["/app/scanner-clair"]

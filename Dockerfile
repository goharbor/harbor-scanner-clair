FROM scratch

ADD bin/clair-adapter /app/clair-adapter

ENTRYPOINT ["/app/clair-adapter"]

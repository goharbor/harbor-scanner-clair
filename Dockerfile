FROM scratch

COPY scanner-clair /scanner-clair

ENTRYPOINT ["/scanner-clair"]

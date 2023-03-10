FROM golang:1.20.0 as builder

WORKDIR /app/
COPY go.mod go.mod
COPY go.sum go.sum
RUN go mod download
RUN go get gatekeeper
COPY main.go main.go
COPY acme.go acme.go
COPY dataview.go dataview.go
RUN CGO_ENABLED=0 go build -o /main
RUN chmod 777 /main

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

COPY proxypublic /proxypublic
COPY index.html /index.html
COPY --from=builder /main /main
ARG DATE
LABEL org.opencontainers.image.version=${DATE}
ENTRYPOINT ["/main"]

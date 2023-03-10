FROM golang:1.17 as builder

#WORKDIR /download/
#COPY compile.go .
#RUN go mod init gatekeeper
#RUN go mod tidy
#COPY go.mod go.mod
#COPY go.sum go.sum
#RUN go mod download

RUN apt-get update
RUN apt-get install -y iputils-ping net-tools
WORKDIR /app/
#RUN cp /download/go.mod .
#RUN cp /download/go.sum .
COPY go.mod go.mod
COPY go.sum go.sum
COPY main.go main.go
RUN CGO_ENABLED=0 go build -o /main
RUN chmod 777 /main

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

COPY proxypublic /proxypublic
COPY --from=builder /main /main

ENTRYPOINT ["/main"]

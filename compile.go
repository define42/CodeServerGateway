package main

import (
	"context"
	_ "github.com/caddyserver/certmagic"
	_ "github.com/gabriel-vasile/mimetype"
	_ "github.com/google/uuid"
	_ "github.com/gorilla/mux"
	_ "github.com/gorilla/securecookie"
	_ "github.com/docker/docker/api/types"
	_ "github.com/docker/docker/api/types/container"
	_ "github.com/docker/docker/client"
	_ "github.com/docker/go-connections/nat"
	_ "github.com/docker/docker/api/types/mount"
	_ "github.com/docker/docker/api/types/network"
	_ "github.com/go-ldap/ldap/v3"
	_ "github.com/gamalan/caddy-tlsredis"
)

func main() {

}

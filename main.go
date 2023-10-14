package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"

	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/go-ldap/ldap/v3"
	"github.com/gorilla/securecookie"
)

func DockerClient() (*client.Client, string) {
	cli, err := client.NewEnvClient()
	if err != nil {
		panic(err)
	}

	dockerUsername := os.Getenv("DOCKER_USERNAME")
	dockerPassword := os.Getenv("DOCKER_PASSWORD")
	dockerServer := os.Getenv("DOCKER_SERVER")

	if len(dockerServer) > 0 {
		fmt.Println("dockerUsername:", dockerUsername)
		fmt.Println("dockerPassword:", dockerPassword)
		fmt.Println("dockerServer", dockerServer)

		authConfig := types.AuthConfig{
			Username:      dockerUsername,
			Password:      dockerPassword,
			ServerAddress: dockerServer,
		}
		ok, err := cli.RegistryLogin(context.Background(), authConfig)
		if err != nil {
			panic(err)
		}

		encodedJSON, err := json.Marshal(authConfig)
		if err != nil {
			panic(err)
		}

		authStr := base64.URLEncoding.EncodeToString(encodedJSON)

		fmt.Println("RegistryLogin:", ok.Status, " authStr:", authStr)
		return cli, authStr
	}
	return cli, string("")
}

var dockerClient, IdentityToken = DockerClient()

func getDockerLogs(cid string) string {

	i, err := dockerClient.ContainerLogs(context.Background(), cid, types.ContainerLogsOptions{
		ShowStderr: true,
		ShowStdout: true,
		Timestamps: false,
		Follow:     false,
		Details:    false,
		Tail:       "50",
	})
	if err != nil {
		return ""
	}

	b, err := ioutil.ReadAll(i)
	if err != nil {
		return ""
	}
	output := string(b)

	output = strings.ReplaceAll(output, "\r\n\r\n", "\r\n")
	output = strings.ReplaceAll(output, "\r\n\r\n", "\r\n")
	output = strings.ReplaceAll(output, "\r\n\r\n", "\r\n")
	output = strings.ReplaceAll(output, "\n\n", "\n")
	output = strings.ReplaceAll(output, "\n\n", "\n")
	return output
}

func doContainerExist(name string) bool {
	ctx := context.Background()
	containerList, err := dockerClient.ContainerList(ctx, types.ContainerListOptions{})
	if err != nil {
		fmt.Println("Panic! dockerClient.ContainerList:", err)
		return false
	}
	for _, ctr := range containerList {
		if ctr.Names[0][1:] == "vsc"+name {
			return true
		}
	}
	return false
}

func pullContainer(imageName string) {

	events, err := dockerClient.ImagePull(context.Background(), imageName, types.ImagePullOptions{RegistryAuth: IdentityToken})
	if err != nil {
		panic(err)
	}

	d := json.NewDecoder(events)

	type Event struct {
		Status         string `json:"status"`
		Error          string `json:"error"`
		Progress       string `json:"progress"`
		ProgressDetail struct {
			Current int `json:"current"`
			Total   int `json:"total"`
		} `json:"progressDetail"`
	}

	var event *Event
	for {
		if err := d.Decode(&event); err != nil {
			if err == io.EOF {
				break
			}

			panic(err)
		}

		fmt.Printf("EVENT: %+v\n", event)
	}
	if event != nil {
		if strings.Contains(event.Status, fmt.Sprintf("Downloaded newer image for %s", imageName)) {
			// new
			fmt.Println("new")
		}

		if strings.Contains(event.Status, fmt.Sprintf("Image is up to date for %s", imageName)) {
			// up-to-date
			fmt.Println("up-to-date")
		}
	}
}

func createContainer(name string) {
	ctx := context.Background()
	containerName := "vsc" + name
	userDataFolder := "/data/" + containerName
	err := os.MkdirAll(userDataFolder, 0777)
	if err != nil {
		fmt.Println("Panic! createContainer->MkdirAll:", err)
	}
	err = os.Chmod(userDataFolder, 0777)
	if err != nil {
		fmt.Println("Panic! createContainer->Chmod:", err)
	}

	endpointConfigs := map[string]*network.EndpointSettings{}

	endpointSetting := network.EndpointSettings{}
	endpointConfigs["codeservernetwork"] = &endpointSetting
	networkingConfig := network.NetworkingConfig{
		EndpointsConfig: endpointConfigs,
	}

	dns := []string{}

	dockerDnsServers := os.Getenv("DNS_SERVERS")
	if len(dockerDnsServers) > 0 {
		dns_servers := strings.Split(dockerDnsServers, ",")
		for _, dns_server := range dns_servers {
			fmt.Println("Added DNS server:", dns_server)
			dns = append(dns, dns_server)
		}
	}

	_, err = dockerClient.ContainerCreate(ctx,
		&container.Config{
			Tty:      true,
			Image:    os.Getenv("CODE_SERVER_IMAGE"),
			Hostname: containerName,
			Env:      []string{"GITUSER=" + name, "PUID=1000", "PGID=1000", "TZ=Europe/Copenhagen", "HASHED_PASSWORD=" + passwordSHA256(name), "SUDO_PASSWORD=password", "PORT=8000", "DOCKER_MODS=" + os.Getenv("DOCKER_MODS")},
		},
		&container.HostConfig{
			Privileged:    true,
			DNS:           dns,
			RestartPolicy: container.RestartPolicy{Name: "always"},
			Mounts: []mount.Mount{
				{
					Type:   mount.TypeBind,
					Source: userDataFolder,
					Target: "/config/",
				},
				{
					Type:     mount.TypeBind,
					Source:   "/data/ca/",
					Target:   "/data/ca/",
					ReadOnly: true,
				},
			}},
		&networkingConfig,
		nil,
		containerName)
	if err != nil {
		fmt.Println("Panic! ContainerCreate:", err)
	}

	if err := dockerClient.ContainerStart(ctx, containerName, types.ContainerStartOptions{}); err != nil {
		fmt.Println("Panic! ContainerStart:", err)
	}
}

func passwordSHA256(password string) string {
	password += os.Getenv("HASH_SALT")
	h := sha256.New()
	h.Write([]byte(password))
	dst := make([]byte, hex.EncodedLen(len(h.Sum(nil))))
	hex.Encode(dst, h.Sum(nil))
	return string(dst)
}

func generateSecureCookie() *securecookie.SecureCookie {
	// Hash keys should be at least 32 bytes lon
	var hashKey = make([]byte, 64)
	// 32 bytes (AES-256) long
	var blockKey = make([]byte, 32)

	if len(os.Getenv("COOKIE_HASH_KEY")) >= 32 && len(os.Getenv("COOKIE_BLOCK_KEY")) == 32 {
		fmt.Print("Static Cookie key defined with COOKIE_HASH_KEY and COOKIE_BLOCK_KEY")
		hashKey = []byte(os.Getenv("COOKIE_HASH_KEY"))
		blockKey = []byte(os.Getenv("COOKIE_BLOCK_KEY"))
	} else {
		_, err := rand.Read(hashKey)
		if err != nil {
			panic(err)
		}
		_, err = rand.Read(blockKey)
		if err != nil {
			panic(err)
		}

		fmt.Println("Random Cookie key generated :-)")
	}

	var s = securecookie.New(hashKey, blockKey)
	return s
}

var s = generateSecureCookie()

func login(w http.ResponseWriter, req *http.Request) {
	err := req.ParseForm()
	if err != nil {
		return
	}
	username := req.Form.Get("username")
	password := req.Form.Get("password")

	ldapok, ldapError := ldapLogin(username, password)

	if ldapok {
		fmt.Printf("Login username:%s\n", username)
		if doContainerExist(username) {
			fmt.Println("Container for:", username, " exists")
		} else {
			fmt.Println("Creating container for:", username)
			createContainer(username)
			time.Sleep(5 * time.Second)
		}

		value := map[string]string{
			"username": username,
			"password": password,
		}
		encoded, err := s.Encode("SAFE", value)
		if err == nil {
			cookie := &http.Cookie{
				Name:     "SAFE",
				Value:    encoded,
				Path:     "/",
				Secure:   false,
				HttpOnly: false,
			}
			fmt.Printf("Cookie added \n")
			http.SetCookie(w, cookie)
		}
		if err != nil {
			log.Fatal(err)
		}
		expiration := time.Now().Add(365 * 24 * time.Hour)
		cookie := http.Cookie{Name: "key", Value: passwordSHA256(username), Expires: expiration}
		http.SetCookie(w, &cookie)
		cookie2 := http.Cookie{Name: "code-server-session", Value: passwordSHA256(username), Expires: expiration}
		http.SetCookie(w, &cookie2)
		http.Redirect(w, req, "/dockertools", 307)
		return
	} else {
		c := &http.Cookie{
			Name:     "SAFE",
			Value:    "",
			Path:     "/",
			Expires:  time.Unix(0, 0),
			HttpOnly: false,
		}
		http.SetCookie(w, c)
		c1 := &http.Cookie{
			Name:     "code-server-session",
			Value:    "",
			Path:     "/",
			Expires:  time.Unix(0, 0),
			HttpOnly: false,
		}
		http.SetCookie(w, c1)
		c2 := &http.Cookie{
			Name:     "key",
			Value:    "",
			Path:     "/",
			Expires:  time.Unix(0, 0),
			HttpOnly: false,
		}
		http.SetCookie(w, c2)

		fmt.Fprintf(w, "<html>\r\n<head>\r\n")
		fmt.Fprintf(w, "<link href=\"/proxypublic/bootstrap.css\" rel=\"stylesheet\">\r\n")
		fmt.Fprintf(w, "<link rel=icon href=\"/proxypublic/logo.svg\" type=\"image/svg+xml\">")
		fmt.Fprintf(w, "</head>\r\n")
		fmt.Fprintf(w, "<body><div class=\"container\">\r\n")
		fmt.Fprintf(w, "<div>\r\n")
		fmt.Fprintf(w, "%s\r\n", ldapError)
		fmt.Fprintf(w, "<center><br><h1><font color=\"#0065A9\">Visual Studio Code Gateway</font></h1>")
		fmt.Fprintf(w, "<br><img src=/proxypublic/logo.jpg height=180>\r\n")
		fmt.Fprintf(w, "<br><form action=\"/login\" method=\"post\" class=\"form-signin\">\r\n")
		fmt.Fprintf(w, "<br><table class=\"table table-borderless mx-auto w-auto\">")
		fmt.Fprintf(w, "<tr><th>Login</th></tr>\r\n")
		fmt.Fprintf(w, "<tr><td><input type=\"text\" name=\"username\" placeholder=\"Username\" required autofocus>\r\n</td></tr>")
		fmt.Fprintf(w, "<tr><td><input type=\"password\" name=\"password\" placeholder=\"Password\" required>\r\n</td></tr>")
		fmt.Fprintf(w, "<tr><td><button class=\"btn btn-sm btn-dark float-right\" type=\"submit\">Login</button>\r\n</td></tr>")
		fmt.Fprintf(w, "</table>\r\n")
		fmt.Fprintf(w, "</form>\r\n")
		fmt.Fprintf(w, "</div>\r\n")
		fmt.Fprintf(w, "</body>\r\n")
		fmt.Fprintf(w, "</html>\r\n")
	}

}

func ldapLogin(user string, password string) (bool, string) {
	if len(user) == 0 || len(password) == 0 {
		return false, ""
	}
	response := ""
	tlsConf := &tls.Config{InsecureSkipVerify: true}
	ldapServer := os.Getenv("LDAP_SERVER")
	l, err := ldap.DialTLS("tcp", ldapServer, tlsConf)
	if err != nil {
		fmt.Println("ldap.Dial", err)
		response += fmt.Sprintf("<div class=\"alert alert-danger\" role=\"alert\">Authenticating error: %s</div>", err)
		return false, response
	}
	defer l.Close()

	ldapUserDomain := os.Getenv("LDAP_USER_DOMAIN")
	err = l.Bind(user+"@"+ldapUserDomain, password)
	if err != nil {
		fmt.Println("l.SimpleBind", err)
		response += fmt.Sprintf("<div class=\"alert alert-danger\" role=\"alert\">Authenticating failed for user %s</div>", user)
		return false, response
	}
	return true, response
}

func checkActive(server string) bool {
	timeout := time.Duration(1 * time.Second)
	client := http.Client{
		Timeout: timeout,
	}
	resp, err := client.Get("http://vsc" + server + ":8000")
	if err != nil {
		return false
	}
	if resp.StatusCode == 200 {
		return true
	}
	return false
}

type DockerStatusJson struct {
	Active bool
	Docker types.Container
	Logs   string
}

func dockerstatus(w http.ResponseWriter, r *http.Request, username string) {
	ctx := context.Background()
	containerList, err := dockerClient.ContainerList(ctx, types.ContainerListOptions{})
	if err != nil {
		fmt.Println("Panic! dockerClient.ContainerList:", err)
		return
	}
	for _, ctr := range containerList {
		if ctr.Names[0][1:] == "vsc"+username {
			active := checkActive(username)
			p := DockerStatusJson{Active: active, Docker: ctr, Logs: getDockerLogs("vsc" + username)}
			json.NewEncoder(w).Encode(p)
			return
		}
	}
}

func dockerrecreate(w http.ResponseWriter, r *http.Request, username string) {
	containerName := "vsc" + username
	ctx := context.Background()
	if err := dockerClient.ContainerStop(ctx, containerName, nil); err != nil {
		fmt.Println("Panic! ContainerStart:", err)
	}
	removeOptions := types.ContainerRemoveOptions{
		RemoveVolumes: true,
		Force:         true,
	}
	if err := dockerClient.ContainerRemove(ctx, containerName, removeOptions); err != nil {
		fmt.Println("Panic! ContainerStart:", err)
	}
	createContainer(username)
}

func dockerrestart(w http.ResponseWriter, r *http.Request, username string) {
	containerName := "vsc" + username
	ctx := context.Background()
	if err := dockerClient.ContainerStop(ctx, containerName, nil); err != nil {
		fmt.Println("Panic! ContainerStart:", err)
	}
	if err := dockerClient.ContainerStart(ctx, containerName, types.ContainerStartOptions{}); err != nil {
		fmt.Println("Panic! ContainerStart:", err)
	}
}

type SecurityHandle func(w http.ResponseWriter, r *http.Request, username string)

func Security(next SecurityHandle) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("SAFE")
		var username = ""
		if err == nil {
			value := make(map[string]string)
			if err = s.Decode("SAFE", cookie.Value, &value); err == nil {
				username = value["username"]
			}
		}
		if len(username) > 0 {
			next(w, r, username)
		} else {
			login(w, r)
		}

	})
}

func dockertools(w http.ResponseWriter, r *http.Request, username string) {
	http.ServeFile(w, r, "index.html")
}

func defaultTransportDialContext(dialer *net.Dialer) func(context.Context, string, string) (net.Conn, error) {
	return dialer.DialContext
}

var DefaultTransport http.RoundTripper = &http.Transport{
	DialContext: defaultTransportDialContext(&net.Dialer{
		Timeout:   30000 * time.Second,
		KeepAlive: 30000 * time.Second,
	}),
	ForceAttemptHTTP2:     true,
	MaxIdleConns:          10000,
	IdleConnTimeout:       90000 * time.Second,
	TLSHandshakeTimeout:   10000 * time.Second,
	ExpectContinueTimeout: 10000 * time.Second,
}

func main() {
	err := os.MkdirAll("/data/ca/", 0777)

	if err != nil {
		fmt.Println("Panic! create folder /data/ca/:", err)
	}

	time.Sleep(1 * time.Second)
	disableDownload := os.Getenv("CODE_SERVER_IMAGE_DISABLE")
	if len(disableDownload) == 0 {
		pullContainer(os.Getenv("CODE_SERVER_IMAGE"))
	}

	dockerMods := os.Getenv("DOCKER_MODS")
	if len(dockerMods) > 0 {
		mods := strings.Split(dockerMods, "|")
		for _, mod := range mods {
			fmt.Println("Downloading image:", mod)
			pullContainer(mod)
		}
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("SAFE")
		var username = ""
		if err == nil {
			value := make(map[string]string)
			if err = s.Decode("SAFE", cookie.Value, &value); err == nil {
				username = value["username"]
			}
		}
		if len(username) > 0 {
			director := func(req *http.Request) {
				req.URL.Scheme = "http"
				req.URL.Host = "vsc" + username + ":8000"
			}

			proxy := &httputil.ReverseProxy{Director: director}

			proxy.ServeHTTP(w, r)
		} else {
			login(w, r)
		}
	})

	mux.HandleFunc("/disconnect", login)
	mux.Handle("/dockerrecreate", Security(dockerrecreate))
	mux.Handle("/dockerrestart", Security(dockerrestart))
	mux.Handle("/dockertools", Security(dockertools))
	mux.Handle("/logout", Security(dockertools)) //This is Sign out from VS
	mux.Handle("/dockerstatus", Security(dockerstatus))

	fileServerPublic := http.FileServer(http.Dir("/proxypublic"))
	mux.Handle("/proxypublic/", http.StripPrefix("/proxypublic", fileServerPublic))

	server_domain := os.Getenv("SERVER_DOMAIN")
	acme_server := os.Getenv("ACME_SERVER")

	if len(server_domain) > 0 && len(acme_server) > 0 {
		log.Fatal(HTTPSACME([]string{server_domain}, mux, acme_server))
	} else {
		fmt.Printf("unencrypted server\n")
		err := http.ListenAndServe(":80", mux)
		if err != nil {
			panic(err)
		}
	}
}

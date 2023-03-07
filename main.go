package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	//	"encoding/json"
	"fmt"
	"github.com/caddyserver/certmagic"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/go-ldap/ldap/v3"
	"github.com/gorilla/securecookie"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"time"
)

func DockerClient() *client.Client {
	cli, err := client.NewEnvClient()
	if err != nil {
		panic(err)
	}
	return cli
}

var dockerClient = DockerClient()

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

	_, err = dockerClient.ContainerCreate(ctx,
		&container.Config{
			Image:    os.Getenv("CODE_SERVER_IMAGE"),
			Hostname: containerName,
			Env:      []string{"GITUSER=" + name, "PUID=1000", "PGID=1000", "TZ=Europe/Copenhagen", "HASHED_PASSWORD=" + passwordSHA256(name), "SUDO_PASSWORD=password", "PORT=80"},
		},
		&container.HostConfig{
			Privileged:    true,
			RestartPolicy: container.RestartPolicy{Name: "always"},
			Mounts: []mount.Mount{
				{
					Type:   mount.TypeBind,
					Source: userDataFolder,
					Target: "/config/",
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
		fmt.Println("Random Cookie key generated")
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

	ldapok, ldapError := ldapLogin2(username, password)

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
		http.Redirect(w, req, "/dockertools", 301)
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

		fmt.Fprintf(w, "<html>\r\n<head>\r\n")
		fmt.Fprintf(w, "<link href=\"/proxypublic/bootstrap.css\" rel=\"stylesheet\">\r\n")
		fmt.Fprintf(w, "<link rel=icon href=\"favicon.ico\" type=\"image/x-icon\">")
		fmt.Fprintf(w, "</head>\r\n")
		fmt.Fprintf(w, "<body><div class=\"container\">\r\n")
		fmt.Fprintf(w, "<div>\r\n")
		fmt.Fprintf(w, "%s\r\n", ldapError)
		fmt.Fprintf(w, "<form action=\"/login\" method=\"post\" class=\"form-signin\">\r\n")
		fmt.Fprintf(w, "<br><table class=\"table table-borderless mx-auto w-auto\">")
		fmt.Fprintf(w, "<tr><td><img src=/proxypublic/vscode.svg height=180></td></tr>")
		fmt.Fprintf(w, "<tr><th>Login</th></tr>\r\n")
		fmt.Fprintf(w, "<tr><td><input type=\"text\" name=\"username\" placeholder=\"Username\" required autofocus>\r\n</td></tr>")
		fmt.Fprintf(w, "<tr><td><input type=\"password\" name=\"password\" placeholder=\"Password\" required>\r\n</td></tr>")
		fmt.Fprintf(w, "<tr><td><button class=\"btn btn-sm btn-dark btn-block\" type=\"submit\">Login</button>\r\n</td></tr>")
		fmt.Fprintf(w, "</table>\r\n")
		fmt.Fprintf(w, "</form>\r\n")
		fmt.Fprintf(w, "</div>\r\n")
		fmt.Fprintf(w, "</body>\r\n")
		fmt.Fprintf(w, "</html>\r\n")
	}

}

func ldapBindTest() {
	tlsConf := &tls.Config{InsecureSkipVerify: true}
	ldapServer := os.Getenv("LDAP_SERVER")
	l, err := ldap.DialTLS("tcp", ldapServer, tlsConf)
	if err != nil {
		fmt.Println("Panic! connection with ldap server", err)
		return
	}
	defer l.Close()
	bindusername := os.Getenv("BIND_USER")
	bindpassword := os.Getenv("BIND_PASSWORD")

	err = l.Bind(bindusername, bindpassword)
	if err != nil {
		fmt.Println("Bind failed:", err)
	}
	fmt.Println("Testing ldap-connection with Bind: OK")
}

func ldapLogin2(user string, password string) (bool, string) {
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
	bindusername := os.Getenv("BIND_USER")
	bindpassword := os.Getenv("BIND_PASSWORD")
	basedn := os.Getenv("BASE_DN")

	err = l.Bind(bindusername, bindpassword)
	if err != nil {
		fmt.Println("Bind:", err)
		response += fmt.Sprintf("<div class=\"alert alert-danger\" role=\"alert\">Authenticating failed for user %s</div>", user)
		return false, response
	}

	searchRequest := ldap.NewSearchRequest(
		basedn,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&(uid=%s))", user),
		[]string{"dn"},
		nil,
	)
	sr, err := l.Search(searchRequest)
	if err != nil {
		fmt.Println("Search:", err)
		response += fmt.Sprintf("<div class=\"alert alert-danger\" role=\"alert\">Authenticating failed for user %s</div>", user)
		return false, response
	}

	if len(sr.Entries) != 1 {
		fmt.Println("User does not exist or too many entries returned")
		fmt.Println("sr.Entries:", sr.Entries)
		response += fmt.Sprintf("<div class=\"alert alert-danger\" role=\"alert\">Authenticating failed for user %s</div>", user)
		return false, response
	}
	userdn := sr.Entries[0].DN
	err = l.Bind(userdn, password)
	if err != nil {
		fmt.Println("l.SimpleBind", err)
		response += fmt.Sprintf("<div class=\"alert alert-danger\" role=\"alert\">Authenticating failed for user %s</div>", user)
		return false, response
	}
	return true, response
}
func getIcon(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "/proxypublic/favicon.ico")
}

func tools(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	containerList, err := dockerClient.ContainerList(ctx, types.ContainerListOptions{})
	if err != nil {
		fmt.Println("Panic! dockerClient.ContainerList:", err)
		return
	}
	for _, ctr := range containerList {
		fmt.Println(ctr.Names[0][1:])

	}
}

func dockertools(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("SAFE")
	var username = ""
	if err == nil {
		value := make(map[string]string)
		if err = s.Decode("SAFE", cookie.Value, &value); err == nil {
			username = value["username"]
		}
	}
	if len(username) > 0 {

		ctx := context.Background()
		keys, ok := r.URL.Query()["action"]

		if ok && len(keys[0]) > 0 {

			action := keys[0]
			containerName := "vsc" + username
			if action == "restart" {
				if err := dockerClient.ContainerStop(ctx, containerName, nil); err != nil {
					fmt.Println("Panic! ContainerStart:", err)
				}
				if err := dockerClient.ContainerStart(ctx, containerName, types.ContainerStartOptions{}); err != nil {
					fmt.Println("Panic! ContainerStart:", err)
				}
				fmt.Println("##################################3 restarted")
			}
			if action == "start" {
				if err := dockerClient.ContainerStart(ctx, containerName, types.ContainerStartOptions{}); err != nil {
					fmt.Println("Panic! ContainerStart:", err)
				}
				fmt.Println("##################################3 Start")
			}
			if action == "stop" {
				if err := dockerClient.ContainerStop(ctx, containerName, nil); err != nil {
					fmt.Println("Panic! ContainerStart:", err)
				}
				fmt.Println("##################################3 Stop")
			}
			if action == "recreate" {
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
				fmt.Println("##################################3 reCreated")
			}

		}

		fmt.Fprintf(w, "<html><head><link href=/proxypublic/bootstrap.css rel=stylesheet></head>")
		fmt.Fprint(w, "<table class=\"table table-hover\"><tr>")
		fmt.Fprintln(w, "<th><a href=/logout>Logout</a></td></th>")
		containerList, err := dockerClient.ContainerList(ctx, types.ContainerListOptions{All: true})
		if err != nil {
			fmt.Println("Panic! dockerClient.ContainerList:", err)
			return
		}
		for _, ctr := range containerList {
			//      fmt.Println(ctr)

			/*
				b, err := json.Marshal(ctr)
				if err != nil {
					fmt.Println(err)
					return
				}*/
			if ctr.Names[0][1:] == "vsc"+username {
				fmt.Fprintf(w, "<tr>")
				fmt.Fprintf(w, "<th></th>")
				fmt.Fprintf(w, "<th></th>")
				fmt.Fprintf(w, "<th></th>")
				fmt.Fprintf(w, "<th>Image</th>")
				fmt.Fprintf(w, "<th>State</th>")
				fmt.Fprintf(w, "<th>Status</th>")
				fmt.Fprintf(w, "<th>Image</th>")
				fmt.Fprintf(w, "<th>Created</th>")
				fmt.Fprintf(w, "</tr>")
				fmt.Fprintf(w, "<tr>")
				fmt.Fprintln(w, "<td><a href=/dockertools?action=restart>Restart</a></td>")
				fmt.Fprintln(w, "<td><a href=/dockertools?action=recreate>ReCreate</a></td>")
				fmt.Fprintln(w, "<td><a href=/>Connect</a></td>")
				fmt.Fprintf(w, "<td>%v</td>", ctr.Image)
				fmt.Fprintf(w, "<td>%v</td>", ctr.State)
				fmt.Fprintf(w, "<td>%v</td>", ctr.Status)
				fmt.Fprintf(w, "<td>%v</td>", ctr.Image)
				fmt.Fprintf(w, "<td>%v</td>", time.Unix(ctr.Created, 0))
				fmt.Fprintf(w, "</tr>")
				//				fmt.Fprintf(w, "<tr><td colspan=4>%v</td></tr>", string(b))
			}

		}
		fmt.Fprintf(w, "</table>")
	} else {
		login(w, r)
	}
}

func main() {
	time.Sleep(1 * time.Second)
	ldapBindTest()
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
				req.URL.Host = "vsc" + username
			}

			proxy := &httputil.ReverseProxy{Director: director}

			proxy.ServeHTTP(w, r)
		} else {
			login(w, r)
		}
	})

	mux.HandleFunc("/logout", login)
	mux.HandleFunc("/tools", tools)
	mux.HandleFunc("/dockertools", dockertools)

	fileServerPublic := http.FileServer(http.Dir("/proxypublic"))
	mux.Handle("/proxypublic/", http.StripPrefix("/proxypublic", fileServerPublic))
	mux.HandleFunc("/favicon.ico", getIcon)

	server_domain := os.Getenv("SERVER_DOMAIN")
	acme_server := os.Getenv("ACME_SERVER")

	if len(server_domain) > 0 && len(acme_server) > 0 {
		certmagic.DefaultACME.Agreed = true
		certmagic.DefaultACME.CA = acme_server
		log.Fatal(certmagic.HTTPS([]string{server_domain}, mux))
	} else {
		fmt.Printf("unencrypted server\n")
		err := http.ListenAndServe(":80", mux)
		if err != nil {
			panic(err)
		}
	}
}

package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"path/filepath"

	"os"
)

func isDirectory(path string) (bool, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return false, err
	}

	return fileInfo.IsDir(), err
}


func DataView(next http.Handler) SecurityHandle {
	return func(w http.ResponseWriter, r *http.Request, username string) {

		if !strings.HasPrefix(r.URL.String(), "/fileexplorervsc/vsc"+username) {
			http.Redirect(w, r, "/fileexplorervsc/vsc"+username, 307)
		}

		path := filepath.Join(strings.Replace(r.URL.String(), "/fileexplorervsc/", "/data/", -1))

		what, _ := isDirectory(path)
		if !what {
			next.ServeHTTP(w, r)
			return
		}
		
		fmt.Fprintf(w, "<html>\r\n<head>\r\n")
                fmt.Fprintf(w, "<link href=\"/proxypublic/bootstrap.css\" rel=\"stylesheet\">\r\n")
                fmt.Fprintf(w, "<link rel=icon href=\"/proxypublic/logo.svg\" type=\"image/svg+xml\">")
                fmt.Fprintf(w, "</head>\r\n")
		fmt.Fprintf(w, "<a class=\"btn btn-outline-dark\" href=/dockertools><img width=30 src=/proxypublic/logo.svg>Menu</a>")

		split := strings.Split(r.URL.String(), "/")
		for idx, sp := range split {
			fmt.Fprintf(w,"<a href=\"/%v\">/%v</a>", filepath.Join(split[1:idx+1]...), sp)
		}

		fmt.Fprintln(w, "<br>")
//		fmt.Fprintf(w, "<form action=\"./upload\" enctype=\"multipart/form-data\" method=\"post\"><input type=text name=path value=\"%v\" ><input type=\"file\" name=\"myFile\" multiple><input type=\"submit\" value=\"upload\"/></form>", r.URL.String())

		files, err := ioutil.ReadDir(path)
		fmt.Fprintln(w, err)

		fmt.Fprintf(w, "<table class=\"table table-hover\">")
		for _, file := range files {

			viewPath := filepath.Join("/", r.URL.Path, file.Name())
			fmt.Println(viewPath)
			fmt.Fprintf(w, "<tr>")
			if file.IsDir() {
				fmt.Fprintf(w, "<td><img src=/proxypublic/folder.svg></td>")
				fmt.Fprintf(w, "<td><a href=\"%v\">%v</a></td>", viewPath, file.Name())
			} else {
				fmt.Fprintf(w, "<td><img src=/proxypublic/file.svg></td>")
				fmt.Fprintf(w, "<td><a target=\"_blank\" href=\"%v\">%v</a></td>", viewPath, file.Name())
			}

			fmt.Fprintf(w, "<td>%v</td>", file.Size())
			fmt.Fprintf(w, "<td>%v</td>", file.ModTime())

			fmt.Fprintf(w, "</tr>")

		}
		fmt.Fprintf(w, "</table>")
	}
}

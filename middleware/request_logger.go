package middleware

import (
	"log"
	"net/http"
	"os"
	"strings"
)

// Logger is ...
type Logger struct {
	Handler http.Handler
}

func (l *Logger) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.SetOutput(os.Stdout)

	method := r.Method
	uri := r.URL.String()
	var request strings.Builder

	request.WriteString("\r\n******** REQUEST ********\r\n" + method + " " + uri + "\r\n")

	for key, val := range r.Header {
		request.WriteString(key + ": ")

		for _, item := range val {
			request.WriteString(item + " \r\n")
		}
	}

	request.WriteString("******** END REQUEST ********\r\n")

	log.Println(request.String())
	l.Handler.ServeHTTP(w, r)
}

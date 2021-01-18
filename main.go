package main

import (
	"aes-encryptor/main/aes"
	"aes-encryptor/main/middleware"
	"html/template"
	"log"
	"net/http"
	"os"

	"github.com/julienschmidt/httprouter"
)

var tpl *template.Template

func init() {
	tpl = template.Must(template.ParseFiles("./view/index.html"))
}

func main() {
	r := httprouter.New()
	PORT := ":5000"

	r.GET("/", index)
	r.POST("/encode", aes.Run)

	mode, dExists := os.LookupEnv("DEPLOY_MODE")
	if !dExists {
		log.Println("Cannot get DEPLOY_MODE from .env")
	}

	var handler http.Handler

	if mode == "development" {
		handler = &middleware.Logger{Handler: r}
	} else {
		handler = r
	}

	log.Printf("Listening on %s\n", PORT)
	log.Fatal(http.ListenAndServe(PORT, handler))
}

func index(w http.ResponseWriter, _ *http.Request, _ httprouter.Params) {
	w.Header().Set("Content-Type", "text/html charset=utf8")
	w.WriteHeader(http.StatusOK)

	if err := tpl.Execute(w, nil); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
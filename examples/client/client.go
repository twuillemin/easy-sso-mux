package main

import (
	"log"
	"net/http"

	"bitbucket.org/twuillemin/easy-sso-mux/pkg/ssomiddleware"
	"github.com/gorilla/mux"
)

func main() {

	// Create a new handler
	r := mux.NewRouter()
	r.HandleFunc("/", helloHandler)

	// Create a new instance of the middleware
	ssoMiddleware, err := ssomiddleware.New("publicKeyFileName.pub")
	if err != nil {
		log.Fatal(err)
	}

	// Add the middleware to the endpoint
	r.Use(ssoMiddleware.Middleware)
}

func helloHandler(w http.ResponseWriter, r *http.Request) {

	authentication, err := ssomiddleware.GetSsoAuthentication(r)
	if err != nil {
		log.Fatal("helloHandler: Unable to do get the authentication information", err)
	}

	w.Write([]byte("Hello " + authentication.User))
}

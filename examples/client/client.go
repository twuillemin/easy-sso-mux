package main

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/twuillemin/easy-sso-mux/pkg/ssomiddleware"
)

func main() {

	// Create a new handler
	r := mux.NewRouter()
	r.HandleFunc("/", helloHandler)

	// Create a new instance of the middleware
	authenticationMiddleware, err := ssomiddleware.New("publicKeyFileName.pub")
	if err != nil {
		log.Fatal(err)
	}

	// Add the middleware to the endpoint
	r.Use(authenticationMiddleware.Middleware)
}

func helloHandler(w http.ResponseWriter, r *http.Request) {

	authentication, err := ssomiddleware.GetSsoAuthentication(r)
	if err != nil {
		log.Fatal("helloHandler: Unable to do get the authentication information", err)
	}

	w.Write([]byte("Hello " + authentication.User))
}

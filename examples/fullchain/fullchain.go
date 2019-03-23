package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/twuillemin/easy-sso-common/pkg/common"
	"github.com/twuillemin/easy-sso-mux/pkg/ssomiddleware"
)

const basePath string = "C:\\Users\\thwui\\go\\src\\github.com\\twuillemin\\easy-sso-mux\\examples\\fullchain"

func main() {

	err := os.Chdir(basePath)
	if err != nil {
		panic(err)
	}

	go createServer()

	sendQuery()
}

func createServer() {
	// Create a new handler
	r := mux.NewRouter()
	r.HandleFunc("/", simpleHandler)

	// Create a new instance of the middleware
	authenticationMiddleware, err := ssomiddleware.NewWithDetailedLogs("signing.pub")
	if err != nil {
		log.Fatal(err)
	}

	// Add the middleware to the endpoint
	r.Use(authenticationMiddleware.Middleware)

	http.ListenAndServe(":8080", r)
}

func sendQuery() {

	// Read the private key for signing token
	privateKeyData, err := ioutil.ReadFile("signing.key")
	if err != nil {
		log.Fatal("sendQuery: Configuration for SSO, attribute privateKeyPath is referencing an unreadable file", err)
	}

	// Get the private key
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyData)
	if err != nil {
		log.Fatal("Configuration for SSO, attribute privateKeyPath is referencing a non-valid file", err)
	}

	// Build the claims
	claims := &common.CustomClaims{
		User:  "user1",
		Roles: []string{"role1", "role2"},
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Unix() + 1000,
			Issuer:    "Example",
		},
	}

	// Build the token
	token := jwt.NewWithClaims(jwt.SigningMethodRS512, claims)

	// Sign the token
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		log.Fatal("sendQuery: Unable to sign generated token", err)
	}

	// Make a request for getting hello
	request, err := http.NewRequest(
		"GET",
		"http://localhost:8080/",
		nil)
	if err != nil {
		log.Fatal("sendQuery: Unable to create request", err)
	}

	// Add the jwt in the query
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokenString))

	// Do the query
	_, err = new(http.Client).Do(request)
	if err != nil {
		log.Fatal("sendQuery: Unable to do the request", err)
	}
}

func simpleHandler(w http.ResponseWriter, r *http.Request) {

	authentication, err := ssomiddleware.GetSsoAuthentication(r)
	if err != nil {
		log.Fatal("simpleHandler: Unable to do get the authentication information", err)
	}

	log.Println("user:", authentication.User)
	log.Println("roles", authentication.Roles)
	log.Println("token", authentication.Token)

	w.Write([]byte("Hello " + authentication.User))
}

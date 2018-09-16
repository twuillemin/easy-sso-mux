package ssomiddleware

import (
	"context"
	"crypto/rsa"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"bitbucket.org/twuillemin/easy-sso-common/pkg/common"
	"github.com/dgrijalva/jwt-go"
)

// AuthenticationInformation holds all the information extracted from an HTTP query, once the query was passed through
// the middleware pipeline
type AuthenticationInformation struct {
	User  string
	Roles []string
	Token string
}

// New creates a new Middleware to be used in with with the given public key. The public key is given as
// the file name having the key stored in a PEM format.
func New(publicKeyFileName string) (*easySSOMuxMiddleware, error) {

	// Read the private key for signing token
	publicKeyData, err := ioutil.ReadFile(publicKeyFileName)
	if err != nil {
		log.Printf("EasySSOMuxMiddleware::New: The given publicKeyFileName parameter is referencing an unreadable file")
		return nil, err
	}

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyData)
	if err != nil {
		log.Printf("EasySSOMuxMiddleware::New: The given publicKeyFileName parameter is referencing a file with unreadble data")
		return nil, err
	}

	return &easySSOMuxMiddleware{
		publicKey: publicKey,
		detailedLogs: true,
	}, nil
}

// Middleware is the function creating the internal function that will be called for each request
func (middleware *easySSOMuxMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(
		func(writer http.ResponseWriter, request *http.Request) {

			authenticationInformation, err := middleware.getUserInformationFromHTTPRequest(request)
			if err != nil {
				switch err {
				case common.ErrMalformedAuthorization:
				case common.ErrTokenMalformed:
					{
						// Write an error and stop the handler chain
						http.Error(writer, "Bad Request", http.StatusBadRequest)
					}
				case common.ErrSignatureInvalid:
				case common.ErrNoAuthorization:
					{
						http.Error(writer, "Unauthorized", http.StatusUnauthorized)
					}
				default:
					{
						http.Error(writer, "Internal Server Error", http.StatusInternalServerError)
					}
				}
			} else {
				if middleware.detailedLogs {
					log.Printf("EasySSOMuxMiddleware::HandlerFunc: authorized user: %v with roles %v", authenticationInformation.User, authenticationInformation.Roles)
				}
				// Build a new request with an updated context
				newRequest := request.WithContext(
					context.WithValue(
						request.Context(),
						authenticationKey,
						authenticationInformation))

				// Update the given request
				*request = *newRequest

				// Pass down the request to the next middleware (or final handler)
				next.ServeHTTP(writer, request)
			}
		})
}

// GetSsoAuthentication retrieves the authentication information from a request
func GetSsoAuthentication(request *http.Request) (*AuthenticationInformation, error) {

	if request == nil {
		return nil, errors.New("no request given")
	}

	// Context is always non nil
	rawValue := request.Context().Value(authenticationKey)
	if rawValue == nil {
		return nil, errors.New("no request does not have authentication information")
	}

	original, ok := rawValue.(*AuthenticationInformation)
	if !ok {
		return nil, errors.New("the authentication information is not readable")
	}

	return original, nil
}

// ssoContextKey is the specific type for storing the authentication information in the context of a request. As by
// official documentation, the use of context implies to use a specific type for keys
type ssoContextKey string

// authenticationKey is the key used to find and retrieve the authentication information from the context
const authenticationKey = ssoContextKey("authentication")

// easySSOMuxMiddleware is the struct keeping the configuration of the middleware
type easySSOMuxMiddleware struct {
	publicKey    *rsa.PublicKey
	detailedLogs bool
}

// getUserInformationFromHTTPRequest locates and validates the authentication token in the given query. If the
// authentication is missing or baf, an error is returned
func (middleware *easySSOMuxMiddleware) getUserInformationFromHTTPRequest(request *http.Request) (*AuthenticationInformation, error) {
	authorization := request.Header.Get("Authorization")

	// If no authorization (8 is the minimum for Bearer + 1 char token)
	if len(authorization) == 0 {
		if middleware.detailedLogs {
			log.Printf("EasySSOMuxMiddleware::getUserInformationFromHTTPRequest: No valid Authorization header")
		}
		return nil, common.ErrNoAuthorization
	}

	// If no authorization (8 is the minimum for Bearer + 1 char token)
	if len(authorization) < 8 {
		if middleware.detailedLogs {
			log.Printf("EasySSOMuxMiddleware::getUserInformationFromHTTPRequest: Malformed Authorization header - Too short")
		}
		return nil, common.ErrMalformedAuthorization
	}

	// Check the format
	bearer := authorization[0:7]
	authorizationValue := authorization[7:]

	if bearer != "Bearer " {
		if middleware.detailedLogs {
			log.Printf("EasySSOMuxMiddleware::getUserInformationFromHTTPRequest: Malformed authorization header - No Bearer found")
		}
		return nil, common.ErrMalformedAuthorization
	}

	// Split by the dots
	parts := strings.Split(authorizationValue, ".")
	if len(parts) != 3 {
		if middleware.detailedLogs {
			log.Printf("EasySSOMuxMiddleware::getUserInformationFromHTTPRequest: Malformed Authorization header - Bad Bearer value")
		}
		return nil, common.ErrMalformedAuthorization
	}

	// Check the signature
	err := jwt.SigningMethodRS512.Verify(strings.Join(parts[0:2], "."), parts[2], middleware.publicKey)
	if err != nil {
		if middleware.detailedLogs {
			log.Printf("EasySSOMuxMiddleware::getUserInformationFromHTTPRequest: Error while verifying the token - Bad signature")
		}
		return nil, common.ErrSignatureInvalid
	}

	// Read the token
	tokenString := authorizationValue
	token, err := jwt.ParseWithClaims(tokenString, &common.CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return middleware.publicKey, nil
	})
	if err != nil {
		if middleware.detailedLogs {
			if middleware.detailedLogs {
				log.Printf("EasySSOMuxMiddleware::getUserInformationFromHTTPRequest: Error while verifying the token - Malformed token")
			}
		}
		return nil, common.ErrTokenMalformed
	}

	// Read the claims
	claims, ok := token.Claims.(*common.CustomClaims) // claims.User and claims.Roles are what we are interested in.
	if !ok {
		if middleware.detailedLogs {
			log.Printf("EasySSOMuxMiddleware::getUserInformationFromHTTPRequest: Error while verifying the token - Malformed claims")
		}
		return nil, common.ErrTokenMalformed
	}

	// Read the timeout
	if claims.ExpiresAt < time.Now().Unix() {
		if middleware.detailedLogs {
			log.Printf("EasySSOMuxMiddleware::getUserInformationFromHTTPRequest: Error while verifying the token - Token too old")
		}
		return nil, common.ErrTokenTooOld
	}

	return &AuthenticationInformation{
		User:  claims.User,
		Roles: claims.Roles,
		Token: authorizationValue,
	}, nil
}

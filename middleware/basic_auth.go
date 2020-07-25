package middleware

import (
	"context"
	"fmt"
	"net/http"
)

// Checks whether a user and password combination is allowed to authenticate
// with the BasicAuthWithAuthenticator simple basic http auth middleware.
// If the authenticator returns a non-nil context, it will be used for handlers
// after this middleware.
type Authenticator interface {
	CheckPassword(ctx context.Context, user string, password string) (bool, context.Context)
}

type MapAuthenticator struct {
	creds map[string]string
}

func (authData MapAuthenticator) CheckPassword(user string, password string) (bool, context.Context) {
	credPass, credUserOk := authData.creds[user]
	return credUserOk && password == credPass, nil
}

// BasicAuth implements a simple middleware handler for adding basic http auth to a route using
// a map of allowed users and passwords.
func BasicAuth(realm string, creds map[string]string) func(next http.Handler) http.Handler {
	return BasicAuthWithAuthenticator(realm, MapAuthenticator{creds})
}

// BasicAuthWithAuthenticator implements a simple middleware handler for adding basic http auth
// to a route using an implementor of thr Authenticator interface.
func BasicAuthWithAuthenticator(realm string, auth Authenticator) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, pass, ok := r.BasicAuth()
			var newCtx context.Context
			if ok {
				ok, newCtx = auth.CheckPassword(r.Context(), user, pass)
			}

			if !ok {
				basicAuthFailed(w, realm)
				return
			}

			if newCtx != nil {
				r = r.WithContext(newCtx)
			}

			next.ServeHTTP(w, r)
		})
	}
}

func basicAuthFailed(w http.ResponseWriter, realm string) {
	w.Header().Add("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, realm))
	w.WriteHeader(http.StatusUnauthorized)
}

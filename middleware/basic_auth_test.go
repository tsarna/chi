package middleware

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/go-chi/chi"
)

func TestBasicAuth(t *testing.T) {
	realm := "myRealm"

	acceptedCreds := map[string]string{
		"gooduser": "goodpassword",
	}

	r := chi.NewRouter()
	r.Use(BasicAuth(realm, acceptedCreds))
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("Hello World"))
	})

	testAuth(t, r, "gooduser", "goodpassword", 200, nil)
	testAuth(t, r, "gooduser", "badpassword", 401, &realm)
	testAuth(t, r, "baduser", "goodpassword", 401, &realm)
	testAuth(t, r, "baduser", "badpassword", 401, &realm)
}

func TestBasicAuthWithAuthenticator(t *testing.T) {
	realm := "myRealm"

	r := chi.NewRouter()
	r.Use(BasicAuthWithAuthenticator(realm, TestAuthenticator{t}))
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("Hello World"))
	})

	testAuth(t, r, "gooduser", "true", 200, nil)
	testAuth(t, r, "gooduser", "false", 401, &realm)
}

func testAuth(t *testing.T, r *chi.Mux, user string, password string, expectedCode int, realm *string) {
	req, _ := http.NewRequest("GET", "/", nil)
	req.SetBasicAuth(user, password)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != expectedCode {
		t.Errorf("With %s:%s expected status code to be %d but got %d", user, password,
			expectedCode, w.Code)
	}

	if realm != nil {
		expected := fmt.Sprintf("Basic realm=\"%s\"", *realm)
		got := w.Header().Get("WWW-Authenticate")
		if !strings.HasPrefix(got, expected) {
			t.Errorf("Expected WWW-Authenticate with realm '%s' but got '%s'", *realm, got)
		}
	}
}

type TestAuthenticator struct {
	t *testing.T
}

func (auth TestAuthenticator) CheckPassword(ctx context.Context, _ string, password string) (bool, context.Context) {
	if ctx == nil {
		auth.t.Errorf("Didn't receive incoming context")
		return false, nil
	}

	authOk, err := strconv.ParseBool(password)
	if err != nil {
		auth.t.Fatalf("Unexpected failure, bad password %s: %s", password, err)
	}

	return authOk, nil
}

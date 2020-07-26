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
		"user": "password",
	}

	r := chi.NewRouter()
	r.Use(BasicAuth(realm, acceptedCreds))
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("Hello World"))
	})

	testAuth(t, r, "user", "password", 200, "Hello World", nil)
	testAuth(t, r, "user", "bad", 401, "", &realm)
	testAuth(t, r, "bad", "password", 401, "", &realm)
	testAuth(t, r, "bad", "bad", 401, "", &realm)
}

func TestBasicAuthWithAuthenticator(t *testing.T) {
	realm := "myRealm"

	r := chi.NewRouter()
	r.Use(BasicAuthWithAuthenticator(realm, TestAuthenticator{t}))
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		user := getUserName(r.Context())
		if user != "" {
			_, _ = w.Write([]byte("Hi " + user))
		} else {
			_, _ = w.Write([]byte("Hello World"))
		}
	})

	// Test unaltered context
	testAuth(t, r, "", "true", 200, "Hello World", nil)
	testAuth(t, r, "", "false", 401, "", &realm)

	// Test that authenticator is able to add values to the context
	testAuth(t, r, "Bob", "true", 200, "Hi Bob", nil)
	testAuth(t, r, "Bob", "false", 401, "", &realm)
}

func testAuth(t *testing.T, r *chi.Mux, user string, password string, expectedCode int, expectedBody string, realm *string) {
	req, _ := http.NewRequest("GET", "/", nil)
	req.SetBasicAuth(user, password)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != expectedCode {
		t.Errorf("With %s:%s expected status code to be %d but got %d", user, password,
			expectedCode, w.Code)
	}

	if w.Code == 200 {
		body := w.Body.String()
		if body != expectedBody {
			t.Errorf(" Got '%s' instead of expected body '%s'", body, expectedBody)
		}
	}

	if realm != nil {
		expected := fmt.Sprintf("Basic realm=\"%s\"", *realm)
		got := w.Header().Get("WWW-Authenticate")
		if !strings.HasPrefix(got, expected) {
			t.Errorf("Expected WWW-Authenticate with realm '%s' but got '%s'", *realm, got)
		}
	}
}

type ctxKeyUserName int

const UserNameKey ctxKeyUserName = 0

type TestAuthenticator struct {
	t *testing.T
}

func (auth TestAuthenticator) CheckPassword(ctx context.Context, user string, password string) (bool, context.Context) {
	if ctx == nil {
		auth.t.Errorf("Didn't receive incoming context")
		return false, nil
	}

	authOk, err := strconv.ParseBool(password)
	if err != nil {
		auth.t.Fatalf("Unexpected failure, bad password %s: %s", password, err)
	}

	var newCtx context.Context
	if user != "" {
		newCtx = context.WithValue(ctx, UserNameKey, user)
	}

	return authOk, newCtx
}

func getUserName(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if username, ok := ctx.Value(UserNameKey).(string); ok {
		return username
	}
	return ""
}

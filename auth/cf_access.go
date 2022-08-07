package auth

import (
	"fmt"
	"net/http"
	"os"

	oidc "github.com/coreos/go-oidc"
	"github.com/filebrowser/filebrowser/v2/errors"
	"github.com/filebrowser/filebrowser/v2/settings"
	"github.com/filebrowser/filebrowser/v2/users"
)

// MethodCFAccessAuth is used to identify cloudflare access auth.
const MethodCFAccessAuth settings.AuthMethod = "cf_access"

type Claims struct {
	Email          string `json:"email"`
	ExpirationTime int64  `json:"exp"`
	IssuedAt       int64  `json:"iat"`
	Issuer         string `json:"iss"`
	Subject        string `json:"sub"`
}

// CloudflareAccessAuth is a Cloudflare Access implementation of an auther.
type CloudflareAccessAuth struct {
	TeamName  string
	PolicyAUD string
}

// Auth authenticates the user via an HTTP header.
func (a CloudflareAccessAuth) Auth(r *http.Request, usr users.Store, stg *settings.Settings, srv *settings.Server) (*users.User, error) {
	teamDomain := fmt.Sprintf("https://%s.cloudflareaccess.com", a.TeamName)
	certsURL := fmt.Sprintf("%s/cdn-cgi/access/certs", teamDomain)

	config := &oidc.Config{
		ClientID: a.PolicyAUD,
	}

	ctx := r.Context()

	keySet := oidc.NewRemoteKeySet(ctx, certsURL)
	verifier := oidc.NewVerifier(teamDomain, keySet, config)

	headers := r.Header
	accessJWT := headers.Get("Cf-Access-Jwt-Assertion")
	if accessJWT == "" {
		return nil, fmt.Errorf("No token on the request")
	}

	// Verify the access token
	token, err := verifier.Verify(ctx, accessJWT)
	if err != nil {
		return nil, fmt.Errorf("Invalid token: %w", err)
	}

	var claims Claims
	if err := token.Claims(&claims); err != nil {
		return nil, fmt.Errorf("Cannot unmarshal the token payload: %w", err)
	}

	user, err := usr.Get(srv.Root, claims.Email)
	if err == errors.ErrNotExist {
		return nil, os.ErrPermission
	}

	return user, err
}

// LoginPage tells that proxy auth doesn't require a login page.
func (a CloudflareAccessAuth) LoginPage() bool {
	return false
}

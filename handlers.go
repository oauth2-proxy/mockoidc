package mockoidc

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

const (
	applicationJSON = "application/json"

	authorizeEndpoint = "/authorize"
	tokenEndpoint     = "/token"
	userinfoEndpoint  = "/userinfo"
	jwksEndpoint      = "/.well-known/jwks.json"
	discoveryEndpoint = "/.well-known/openid-configuration"
)

// Authorize implements the `authorization_endpoint` in the OIDC flow.
// It is the initial request that "authenticates" a user in the OAuth2
// flow and redirects the client to the application `redirect_uri`.
func (m *MockOIDC) Authorize(rw http.ResponseWriter, req *http.Request) {
	valid := validateParams(
		[]string{"scope", "state", "client_id", "response_type", "redirect_uri"}, rw, req)
	if !valid {
		return
	}

	clientID := req.Form.Get("client_id")
	if m.ClientID != clientID {
		errorResponse(rw, fmt.Sprintf("Invalid client id: %s", clientID),
			http.StatusUnauthorized)
		return
	}

	session, err := m.SessionStore.NewSession(
		req.Form.Get("scope"),
		req.Form.Get("state"),
		req.Form.Get("nonce"),
		m.UserQueue.Pop(),
	)
	if err != nil {
		errorResponse(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	redirectURI, err := url.Parse(req.Form.Get("redirect_uri"))
	if err != nil {
		errorResponse(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	params, _ := url.ParseQuery(redirectURI.RawQuery)
	params.Set("code", session.SessionID)
	params.Set("state", req.Form.Get("state"))
	redirectURI.RawQuery = params.Encode()

	http.Redirect(rw, req, redirectURI.String(), http.StatusFound)
}

type tokenResponse struct {
	AccessToken  string        `json:"access_token,omitempty"`
	RefreshToken string        `json:"refresh_token,omitempty"`
	IDToken      string        `json:"id_token,omitempty"`
	TokenType    string        `json:"token_type"`
	ExpiresIn    time.Duration `json:"expires_in"`
}

// Token implements the `token_endpoint` in OIDC and responds to requests
// from the application servers that contain the client ID & Secret along
// with the code from the `authorization_endpoint`. It returns the various
// OAuth tokens to the application server for the User authenticated by the
// during the `authorization_endpoint` request (persisted across requests via
// the `code`).
// TODO (@NickMeves): Handle Token Refresh
func (m *MockOIDC) Token(rw http.ResponseWriter, req *http.Request) {
	err := req.ParseForm()
	if err != nil {
		errorResponse(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	valid := validateParams([]string{"client_id", "client_secret", "code"}, rw, req)
	if !valid {
		return
	}

	clientID := req.Form.Get("client_id")
	if subtle.ConstantTimeCompare([]byte(m.ClientID), []byte(clientID)) == 0 {
		errorResponse(rw, fmt.Sprintf("Invalid client id: %s", clientID),
			http.StatusUnauthorized)
		return
	}
	clientSecret := req.Form.Get("client_secret")
	if subtle.ConstantTimeCompare([]byte(m.ClientSecret), []byte(clientSecret)) == 0 {
		errorResponse(rw, fmt.Sprintf("Invalid client secret: %s", clientSecret),
			http.StatusUnauthorized)
		return
	}

	code := req.Form.Get("code")
	session, err := m.SessionStore.GetSessionByID(code)
	if err != nil {
		errorResponse(rw, fmt.Sprintf("Invalid code: %s", code),
			http.StatusUnauthorized)
		return
	}

	tr := &tokenResponse{
		TokenType: "Bearer",
		ExpiresIn: m.RefreshTTL,
	}
	m.setTokens(tr, session)
	if err != nil {
		errorResponse(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	resp, err := json.Marshal(tr)
	if err != nil {
		errorResponse(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonResponse(rw, resp)
}

func (m *MockOIDC) setTokens(tr *tokenResponse, s *Session) error {
	var err error
	tr.AccessToken, err = s.AccessToken(m.Config(), m.Keypair, m.Now())
	if err != nil {
		return err
	}
	tr.RefreshToken, err = s.RefreshToken(m.Config(), m.Keypair, m.Now())
	if err != nil {
		return err
	}
	tr.IDToken, err = s.IDToken(m.Config(), m.Keypair, m.Now())
	if err != nil {
		return err
	}
	return nil
}

// Userinfo returns the User details for the User associated with the passed
// Access Token. Data is scoped down to the session's access scope set in the
// initial `authorization_endpoint` call.
func (m *MockOIDC) Userinfo(rw http.ResponseWriter, req *http.Request) {
	token := m.authorizeToken(rw, req)
	if token == nil {
		return
	}

	session, err := m.SessionStore.GetSessionByToken(token)
	if err != nil {
		errorResponse(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	resp, err := json.Marshal(session.User.scopedClone(session.Scopes))
	if err != nil {
		errorResponse(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonResponse(rw, resp)
}

// TODO (@NickMeves): Implement!
func (m *MockOIDC) Discovery(rw http.ResponseWriter, _ *http.Request) {
	jsonResponse(rw, []byte(`{}`))
}

// JWKS returns the public key in JWKS format to verify in tokens
// signed with our Keypair.PrivateKey.
func (m *MockOIDC) JWKS(rw http.ResponseWriter, _ *http.Request) {
	jwks, err := m.Keypair.JWKS()
	if err != nil {
		errorResponse(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonResponse(rw, jwks)
}

func (m *MockOIDC) authorizeToken(rw http.ResponseWriter, req *http.Request) *jwt.Token {
	authz := req.Header.Get("Authorization")
	parts := strings.Split(authz, " ")
	if len(parts) < 2 || parts[0] != "Bearer" {
		errorResponse(rw, "Invalid authorization header", http.StatusUnauthorized)
		return nil
	}
	token, err := m.Keypair.VerifyJWT(parts[1])
	if err != nil {
		errorResponse(rw, fmt.Sprintf("Invalid token: %v", err), http.StatusUnauthorized)
		return nil
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		errorResponse(rw, "Unable to extract token claims",
			http.StatusInternalServerError)
		return nil
	}
	exp, err := strconv.Atoi(claims["exp"].(string))
	if err != nil {
		errorResponse(rw, err.Error(), http.StatusInternalServerError)
		return nil
	}
	if time.Unix(int64(exp), 0).After(m.Now()) {
		errorResponse(rw, "The token is expired", http.StatusUnauthorized)
		return nil
	}
	return token
}

func validateParams(required []string, rw http.ResponseWriter, req *http.Request) bool {
	for _, param := range required {
		if req.Form.Get(param) != "" {
			continue
		}

		errorResponse(
			rw,
			fmt.Sprintf("The request is missing the required parameter: %s", param),
			http.StatusBadRequest,
		)
		return false
	}
	return true
}

func errorResponse(rw http.ResponseWriter, message string, statusCode int) {
	errJSON := map[string]string{
		"error": message,
	}
	resp, err := json.Marshal(errJSON)
	if err != nil {
		http.Error(rw, message, http.StatusInternalServerError)
	}

	rw.Header().Set("Content-Type", applicationJSON)
	rw.WriteHeader(statusCode)
	rw.Write(resp)
}

func jsonResponse(rw http.ResponseWriter, data []byte) {
	rw.Header().Set("Content-Type", applicationJSON)
	rw.WriteHeader(http.StatusOK)
	rw.Write(data)
}

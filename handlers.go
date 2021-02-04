package mockoidc

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
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

	invalidRequest       = "invalid_request"
	invalidClient        = "invalid_client"
	invalidGrant         = "invalid_grant"
	unsupportedGrantType = "unsupported_grant_type"
	//invalidScope       = "invalid_scope"
	//unauthorizedClient = "unauthorized_client"
)

// Authorize implements the `authorization_endpoint` in the OIDC flow.
// It is the initial request that "authenticates" a user in the OAuth2
// flow and redirects the client to the application `redirect_uri`.
func (m *MockOIDC) Authorize(rw http.ResponseWriter, req *http.Request) {
	err := req.ParseForm()
	if err != nil {
		internalServerError(rw, err.Error())
		return
	}

	valid := assertPresence(
		[]string{"scope", "state", "client_id", "response_type", "redirect_uri"}, rw, req)
	if !valid {
		return
	}

	validClient := assertEqual("client_id", m.ClientID,
		invalidClient, "Invalid client id", rw, req)
	if !validClient {
		return
	}
	validType := assertEqual("response_type", "code",
		unsupportedGrantType, "Invalid response type", rw, req)
	if !validType {
		return
	}

	session, err := m.SessionStore.NewSession(
		req.Form.Get("scope"),
		req.Form.Get("state"),
		req.Form.Get("nonce"),
		m.UserQueue.Pop(),
	)
	if err != nil {
		internalServerError(rw, err.Error())
		return
	}

	redirectURI, err := url.Parse(req.Form.Get("redirect_uri"))
	if err != nil {
		internalServerError(rw, err.Error())
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
// Reference: https://www.oauth.com/oauth2-servers/access-tokens/access-token-response/
// TODO (@NickMeves): Handle Token Refresh
func (m *MockOIDC) Token(rw http.ResponseWriter, req *http.Request) {
	err := req.ParseForm()
	if err != nil {
		internalServerError(rw, err.Error())
		return
	}

	ok := m.sharedParamsValidator(rw, req)
	if !ok {
		return
	}

	var session *Session
	grantType := req.Form.Get("grant_type")
	switch grantType {
	case "authorization_code":
		s, ok := m.accessRequestValidator(rw, req)
		if !ok {
			return
		}
		session = s
	case "refresh_token":
		s, ok := m.refreshRequestValidator(rw, req)
		if !ok {
			return
		}
		session = s
	default:
		errorResponse(rw, invalidRequest, "Invalid grant_type", http.StatusBadRequest)
		return
	}

	tr := &tokenResponse{
		TokenType: "bearer",
		ExpiresIn: m.AccessTTL,
	}
	err = m.setTokens(tr, session)
	if err != nil {
		internalServerError(rw, err.Error())
		return
	}

	if grantType == "refresh_token" {
		tr.RefreshToken = req.Form.Get("refresh_token")
	}

	resp, err := json.Marshal(tr)
	if err != nil {
		internalServerError(rw, err.Error())
		return
	}

	noCache(rw)
	jsonResponse(rw, resp)
}

func (m *MockOIDC) sharedParamsValidator(rw http.ResponseWriter, req *http.Request) bool {
	ok := assertPresence([]string{"client_id", "client_secret", "grant_type"}, rw, req)
	if !ok {
		return false
	}
	equal := assertEqual("client_id", m.ClientID, invalidClient, "Invalid client id", rw, req)
	if !equal {
		return false
	}
	equal = assertEqual("client_secret", m.ClientSecret, invalidClient, "Invalid client secret", rw, req)
	if !equal {
		return false
	}
	return true
}

func (m *MockOIDC) accessRequestValidator(rw http.ResponseWriter, req *http.Request) (*Session, bool) {
	if !m.validateAccessParams(rw, req) {
		return nil, false
	}
	code := req.Form.Get("code")
	session, err := m.SessionStore.GetSessionByID(code)
	if err != nil {
		errorResponse(rw, invalidGrant, fmt.Sprintf("Invalid code: %s", code),
			http.StatusUnauthorized)
		return nil, false
	}
	return session, true
}

func (m *MockOIDC) refreshRequestValidator(rw http.ResponseWriter, req *http.Request) (*Session, bool) {
	if !m.validateRefreshParams(rw, req) {
		return nil, false
	}
	refreshToken := req.Form.Get("refresh_token")
	token, ok := m.authorizeTokenString(refreshToken, rw, req)
	if !ok {
		return nil, false
	}
	session, err := m.SessionStore.GetSessionByToken(token)
	if err != nil {
		errorResponse(rw, invalidGrant, "Invalid refresh token",
			http.StatusUnauthorized)
		return nil, false
	}
	return session, true

}

func (m *MockOIDC) validateAccessParams(rw http.ResponseWriter, req *http.Request) bool {
	// TODO (@NickMeves): Support `redirect_uri` in session and check that here
	valid := assertPresence([]string{"code"}, rw, req)
	if !valid {
		return false
	}

	equal := assertEqual("grant_type", "authorization_code",
		unsupportedGrantType, "Invalid grant type", rw, req)
	if !equal {
		return false
	}

	return true
}

func (m *MockOIDC) validateRefreshParams(rw http.ResponseWriter, req *http.Request) bool {
	// TODO (@NickMeves): Support `redirect_uri` in session and check that here
	valid := assertPresence([]string{"refresh_token"}, rw, req)
	if !valid {
		return false
	}

	equal := assertEqual("grant_type", "refresh_token",
		unsupportedGrantType, "Invalid grant type", rw, req)
	if !equal {
		return false
	}

	return true
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
	token := m.validateBearerToken(rw, req)
	if token == nil {
		return
	}

	session, err := m.SessionStore.GetSessionByToken(token)
	if err != nil {
		internalServerError(rw, err.Error())
		return
	}

	resp, err := session.User.userinfo(session.Scopes)
	if err != nil {
		internalServerError(rw, err.Error())
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
		internalServerError(rw, err.Error())
		return
	}

	jsonResponse(rw, jwks)
}

func (m *MockOIDC) validateBearerToken(rw http.ResponseWriter, req *http.Request) *jwt.Token {
	authz := req.Header.Get("Authorization")
	parts := strings.Split(authz, " ")
	if len(parts) < 2 || parts[0] != "Bearer" {
		errorResponse(rw, invalidRequest, "Invalid authorization header",
			http.StatusUnauthorized)
		return nil
	}

	token, ok := m.authorizeTokenString(parts[1], rw, req)
	if ok {
		return token
	}

	return nil
}

func (m *MockOIDC) authorizeTokenString(tokenString string, rw http.ResponseWriter, req *http.Request) (*jwt.Token, bool) {
	token, err := m.Keypair.VerifyJWT(tokenString)
	if err != nil {
		errorResponse(rw, invalidRequest, fmt.Sprintf("Invalid token: %v", err), http.StatusUnauthorized)
		return nil, false
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		internalServerError(rw, "Unable to extract token claims")
		return nil, false
	}
	exp := claims["exp"].(float64)
	if err != nil {
		internalServerError(rw, err.Error())
		return nil, false
	}
	if m.Now().Unix() > int64(exp) {
		errorResponse(rw, invalidRequest, "The token is expired", http.StatusUnauthorized)
		return nil, false
	}
	return token, true
}

func assertPresence(params []string, rw http.ResponseWriter, req *http.Request) bool {
	for _, param := range params {
		if req.Form.Get(param) != "" {
			continue
		}

		errorResponse(
			rw,
			invalidRequest,
			fmt.Sprintf("The request is missing the required parameter: %s", param),
			http.StatusBadRequest,
		)
		return false
	}
	return true
}

func assertEqual(param, value, errorType, errorMsg string, rw http.ResponseWriter, req *http.Request) bool {
	formValue := req.Form.Get(param)
	if subtle.ConstantTimeCompare([]byte(value), []byte(formValue)) == 0 {
		errorResponse(rw, errorType, fmt.Sprintf("%s: %s", errorMsg, formValue),
			http.StatusUnauthorized)
		return false
	}
	return true
}

func errorResponse(rw http.ResponseWriter, error, description string, statusCode int) {
	errJSON := map[string]string{
		"error":             error,
		"error_description": description,
	}
	resp, err := json.Marshal(errJSON)
	if err != nil {
		http.Error(rw, error, http.StatusInternalServerError)
	}

	noCache(rw)
	rw.Header().Set("Content-Type", applicationJSON)
	rw.WriteHeader(statusCode)

	_, err = rw.Write(resp)
	if err != nil {
		panic(err)
	}
}

func internalServerError(rw http.ResponseWriter, errorMsg string) {
	errorResponse(rw, "internal_server_error", errorMsg, http.StatusInternalServerError)
}

func jsonResponse(rw http.ResponseWriter, data []byte) {
	rw.Header().Set("Content-Type", applicationJSON)
	rw.WriteHeader(http.StatusOK)

	_, err := rw.Write(data)
	if err != nil {
		panic(err)
	}
}

func noCache(rw http.ResponseWriter) {
	rw.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate, max-age=0")
	rw.Header().Set("Pragma", "no-cache")
}

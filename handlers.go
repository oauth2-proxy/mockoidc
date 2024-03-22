package mockoidc

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	IssuerBase            = "/oidc"
	AuthorizationEndpoint = "/oidc/authorize"
	TokenEndpoint         = "/oidc/token"
	UserinfoEndpoint      = "/oidc/userinfo"
	JWKSEndpoint          = "/oidc/.well-known/jwks.json"
	DiscoveryEndpoint     = "/oidc/.well-known/openid-configuration"

	InvalidRequest       = "invalid_request"
	InvalidClient        = "invalid_client"
	InvalidGrant         = "invalid_grant"
	UnsupportedGrantType = "unsupported_grant_type"
	InvalidScope         = "invalid_scope"
	//UnauthorizedClient = "unauthorized_client"
	InternalServerError = "internal_server_error"

	applicationJSON = "application/json"
	openidScope     = "openid"
)

var (
	GrantTypesSupported = []string{
		"authorization_code",
		"refresh_token",
	}
	ResponseTypesSupported = []string{
		"code",
	}
	SubjectTypesSupported = []string{
		"public",
	}
	IDTokenSigningAlgValuesSupported = []string{
		"RS256",
	}
	ScopesSupported = []string{
		"openid",
		"email",
		"groups",
		"profile",
	}
	TokenEndpointAuthMethodsSupported = []string{
		"client_secret_basic",
		"client_secret_post",
	}
	ClaimsSupported = []string{
		"sub",
		"email",
		"email_verified",
		"preferred_username",
		"phone_number",
		"address",
		"groups",
		"iss",
		"aud",
	}
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

	if !validateScope(rw, req) {
		return
	}
	validClient := assertEqual("client_id", m.ClientID,
		InvalidClient, "Invalid client id", rw, req)
	if !validClient {
		return
	}
	validType := assertEqual("response_type", "code",
		UnsupportedGrantType, "Invalid response type", rw, req)
	if !validType {
		return
	}
	if !validateCodeChallengeMethodSupported(rw, req.Form.Get("code_challenge_method"), m.CodeChallengeMethodsSupported) {
		return
	}

	session, err := m.SessionStore.NewSession(
		req.Form.Get("scope"),
		req.Form.Get("nonce"),
		m.UserQueue.Pop(),
		req.Form.Get("code_challenge"),
		req.Form.Get("code_challenge_method"),
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
func (m *MockOIDC) Token(rw http.ResponseWriter, req *http.Request) {
	err := req.ParseForm()
	if err != nil {
		internalServerError(rw, err.Error())
		return
	}

	if !m.validateTokenParams(rw, req) {
		return
	}

	var (
		session *Session
		valid   bool
	)
	grantType := req.Form.Get("grant_type")
	switch grantType {
	case "authorization_code":
		if session, valid = m.validateCodeGrant(rw, req); !valid {
			return
		}

		if !m.validateCodeChallenge(rw, req, session) {
			return
		}
	case "refresh_token":
		if session, valid = m.validateRefreshGrant(rw, req); !valid {
			return
		}
	default:
		errorResponse(rw, InvalidRequest,
			fmt.Sprintf("Invalid grant type: %s", grantType), http.StatusBadRequest)
		return
	}

	tr := &tokenResponse{
		RefreshToken: req.Form.Get("refresh_token"),
		TokenType:    "bearer",
		// expires_in in OAuth2 Token is the lifetime in seconds of the access token
		ExpiresIn: m.AccessTTL / time.Second,
	}
	err = m.setTokens(tr, session, grantType)
	if err != nil {
		internalServerError(rw, err.Error())
		return
	}

	resp, err := json.Marshal(tr)
	if err != nil {
		internalServerError(rw, err.Error())
		return
	}
	noCache(rw)
	jsonResponse(rw, resp)
}

func (m *MockOIDC) validateTokenParams(rw http.ResponseWriter, req *http.Request) bool {
	if !assertPresence([]string{"client_id", "client_secret", "grant_type"}, rw, req) {
		return false
	}

	equal := assertEqual("client_id", m.ClientID,
		InvalidClient, "Invalid client id", rw, req)
	if !equal {
		return false
	}
	equal = assertEqual("client_secret", m.ClientSecret,
		InvalidClient, "Invalid client secret", rw, req)
	if !equal {
		return false
	}

	return true
}

func (m *MockOIDC) validateCodeGrant(rw http.ResponseWriter, req *http.Request) (*Session, bool) {
	if !assertPresence([]string{"code"}, rw, req) {
		return nil, false
	}
	equal := assertEqual("grant_type", "authorization_code",
		UnsupportedGrantType, "Invalid grant type", rw, req)
	if !equal {
		return nil, false
	}

	code := req.Form.Get("code")
	session, err := m.SessionStore.GetSessionByID(code)
	if err != nil || session.Granted {
		errorResponse(rw, InvalidGrant, fmt.Sprintf("Invalid code: %s", code),
			http.StatusUnauthorized)
		return nil, false
	}
	session.Granted = true

	return session, true
}

func (m *MockOIDC) validateCodeChallenge(rw http.ResponseWriter, req *http.Request, session *Session) bool {
	if session.CodeChallenge == "" || session.CodeChallengeMethod == "" {
		return true
	}

	codeVerifier := req.Form.Get("code_verifier")
	if codeVerifier == "" {
		errorResponse(rw, InvalidGrant, "Invalid code verifier. Expected code but client sent none.", http.StatusUnauthorized)
		return false
	}

	challenge, err := GenerateCodeChallenge(session.CodeChallengeMethod, codeVerifier)
	if err != nil {
		errorResponse(rw, InvalidRequest, fmt.Sprintf("Invalid code verifier. %v", err.Error()), http.StatusUnauthorized)
		return false
	}

	if challenge != session.CodeChallenge {
		errorResponse(rw, InvalidGrant, "Invalid code verifier. Code challenge did not match hashed code verifier.", http.StatusUnauthorized)
		return false
	}

	return true
}

func (m *MockOIDC) validateRefreshGrant(rw http.ResponseWriter, req *http.Request) (*Session, bool) {
	if !assertPresence([]string{"refresh_token"}, rw, req) {
		return nil, false
	}

	equal := assertEqual("grant_type", "refresh_token",
		UnsupportedGrantType, "Invalid grant type", rw, req)
	if !equal {
		return nil, false
	}

	refreshToken := req.Form.Get("refresh_token")
	token, authorized := m.authorizeToken(refreshToken, rw)
	if !authorized {
		return nil, false
	}

	session, err := m.SessionStore.GetSessionByToken(token)
	if err != nil {
		errorResponse(rw, InvalidGrant, "Invalid refresh token",
			http.StatusUnauthorized)
		return nil, false
	}
	return session, true
}

func (m *MockOIDC) setTokens(tr *tokenResponse, s *Session, grantType string) error {
	var err error
	tr.AccessToken, err = s.AccessToken(m.Config(), m.Keypair, m.Now())
	if err != nil {
		return err
	}
	if len(s.Scopes) > 0 && s.Scopes[0] == openidScope {
		tr.IDToken, err = s.IDToken(m.Config(), m.Keypair, m.Now())
		if err != nil {
			return err
		}
	}
	if grantType != "refresh_token" {
		tr.RefreshToken, err = s.RefreshToken(m.Config(), m.Keypair, m.Now())
		if err != nil {
			return err
		}
	}
	return nil
}

// Userinfo returns the User details for the User associated with the passed
// Access Token. Data is scoped down to the session's access scope set in the
// initial `authorization_endpoint` call.
func (m *MockOIDC) Userinfo(rw http.ResponseWriter, req *http.Request) {
	token, authorized := m.authorizeBearer(rw, req)
	if !authorized {
		return
	}

	session, err := m.SessionStore.GetSessionByToken(token)
	if err != nil {
		internalServerError(rw, err.Error())
		return
	}

	resp, err := session.User.Userinfo(session.Scopes)
	if err != nil {
		internalServerError(rw, err.Error())
		return
	}
	jsonResponse(rw, resp)
}

type discoveryResponse struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSUri               string `json:"jwks_uri"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`

	GrantTypesSupported               []string `json:"grant_types_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
}

// Discovery renders the OIDC discovery document and partial RFC-8414 authorization
// server metadata hosted at `/.well-known/openid-configuration`.
func (m *MockOIDC) Discovery(rw http.ResponseWriter, _ *http.Request) {
	discovery := &discoveryResponse{
		Issuer:                m.Issuer(),
		AuthorizationEndpoint: m.AuthorizationEndpoint(),
		TokenEndpoint:         m.TokenEndpoint(),
		JWKSUri:               m.JWKSEndpoint(),
		UserinfoEndpoint:      m.UserinfoEndpoint(),

		GrantTypesSupported:               GrantTypesSupported,
		ResponseTypesSupported:            ResponseTypesSupported,
		SubjectTypesSupported:             SubjectTypesSupported,
		IDTokenSigningAlgValuesSupported:  IDTokenSigningAlgValuesSupported,
		ScopesSupported:                   ScopesSupported,
		TokenEndpointAuthMethodsSupported: TokenEndpointAuthMethodsSupported,
		ClaimsSupported:                   ClaimsSupported,
		CodeChallengeMethodsSupported:     m.CodeChallengeMethodsSupported,
	}

	resp, err := json.Marshal(discovery)
	if err != nil {
		internalServerError(rw, err.Error())
		return
	}
	jsonResponse(rw, resp)
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

func (m *MockOIDC) authorizeBearer(rw http.ResponseWriter, req *http.Request) (*jwt.Token, bool) {
	header := req.Header.Get("Authorization")
	parts := strings.SplitN(header, " ", 2)
	if len(parts) < 2 || parts[0] != "Bearer" {
		errorResponse(rw, InvalidRequest, "Invalid authorization header",
			http.StatusUnauthorized)
		return nil, false
	}

	return m.authorizeToken(parts[1], rw)
}

func (m *MockOIDC) authorizeToken(t string, rw http.ResponseWriter) (*jwt.Token, bool) {
	token, err := m.Keypair.VerifyJWT(t, m.Now)
	if err != nil {
		errorResponse(rw, InvalidRequest, fmt.Sprintf("Invalid token: %v", err), http.StatusUnauthorized)
		return nil, false
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		internalServerError(rw, "Unable to extract token claims")
		return nil, false
	}
	exp, ok := claims["exp"].(float64)
	if !ok {
		internalServerError(rw, "Unable to extract token expiration")
		return nil, false
	}
	if m.Now().Unix() > int64(exp) {
		errorResponse(rw, InvalidRequest, "The token is expired", http.StatusUnauthorized)
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
			InvalidRequest,
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

func validateScope(rw http.ResponseWriter, req *http.Request) bool {
	allowed := make(map[string]struct{})
	for _, scope := range ScopesSupported {
		allowed[scope] = struct{}{}
	}

	scopes := strings.Split(req.Form.Get("scope"), " ")
	for _, scope := range scopes {
		if _, ok := allowed[scope]; !ok {
			errorResponse(rw, InvalidScope, fmt.Sprintf("Unsupported scope: %s", scope),
				http.StatusBadRequest)
			return false
		}
	}
	return true
}

func validateCodeChallengeMethodSupported(rw http.ResponseWriter, method string, supportedMethods []string) bool {
	if method != "" && !contains(method, supportedMethods) {
		errorResponse(rw, InvalidRequest, "Invalid code challenge method", http.StatusBadRequest)
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
	errorResponse(rw, InternalServerError, errorMsg, http.StatusInternalServerError)
}

func jsonResponse(rw http.ResponseWriter, data []byte) {
	noCache(rw)
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

func contains(value string, list []string) bool {
	for _, element := range list {
		if element == value {
			return true
		}
	}
	return false
}

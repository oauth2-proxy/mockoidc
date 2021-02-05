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
	IssuerBase        = "/oidc"
	AuthorizeEndpoint = "/oidc/authorize"
	TokenEndpoint     = "/oidc/token"
	UserinfoEndpoint  = "/oidc/userinfo"
	JWKSEndpoint      = "/oidc/.well-known/jwks.json"
	DiscoveryEndpoint = "/oidc/.well-known/openid-configuration"

	InvalidRequest       = "invalid_request"
	InvalidClient        = "invalid_client"
	InvalidGrant         = "invalid_grant"
	UnsupportedGrantType = "unsupported_grant_type"
	//invalidScope       = "invalid_scope"
	//unauthorizedClient = "unauthorized_client"

	applicationJSON = "application/json"
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
		errorResponse(rw, InvalidRequest, "Invalid grant_type", http.StatusBadRequest)
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
	equal := assertEqual("client_id", m.ClientID, InvalidClient, "Invalid client id", rw, req)
	if !equal {
		return false
	}
	equal = assertEqual("client_secret", m.ClientSecret, InvalidClient, "Invalid client secret", rw, req)
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
		errorResponse(rw, InvalidGrant, fmt.Sprintf("Invalid code: %s", code),
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
	token, ok := m.authorizeTokenString(refreshToken, rw)
	if !ok {
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

func (m *MockOIDC) validateAccessParams(rw http.ResponseWriter, req *http.Request) bool {
	// TODO (@NickMeves): Support `redirect_uri` in session and check that here
	valid := assertPresence([]string{"code"}, rw, req)
	if !valid {
		return false
	}

	equal := assertEqual("grant_type", "authorization_code",
		UnsupportedGrantType, "Invalid grant type", rw, req)
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
		UnsupportedGrantType, "Invalid grant type", rw, req)
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
}

// Discovery renders the OIDC discovery document hosted at
// `/.well-known/openid-configuration`.
func (m *MockOIDC) Discovery(rw http.ResponseWriter, _ *http.Request) {
	discovery := &discoveryResponse{
		Issuer:                m.Issuer(),
		AuthorizationEndpoint: m.Issuer() + AuthorizeEndpoint,
		TokenEndpoint:         m.Issuer() + TokenEndpoint,
		JWKSUri:               m.Issuer() + JWKSEndpoint,
		UserinfoEndpoint:      m.Issuer() + UserinfoEndpoint,

		GrantTypesSupported:               GrantTypesSupported,
		ResponseTypesSupported:            ResponseTypesSupported,
		SubjectTypesSupported:             SubjectTypesSupported,
		IDTokenSigningAlgValuesSupported:  IDTokenSigningAlgValuesSupported,
		ScopesSupported:                   ScopesSupported,
		TokenEndpointAuthMethodsSupported: TokenEndpointAuthMethodsSupported,
		ClaimsSupported:                   ClaimsSupported,
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

func (m *MockOIDC) validateBearerToken(rw http.ResponseWriter, req *http.Request) *jwt.Token {
	authz := req.Header.Get("Authorization")
	parts := strings.Split(authz, " ")
	if len(parts) < 2 || parts[0] != "Bearer" {
		errorResponse(rw, InvalidRequest, "Invalid authorization header",
			http.StatusUnauthorized)
		return nil
	}

	token, ok := m.authorizeTokenString(parts[1], rw)
	if ok {
		return token
	}

	return nil
}

func (m *MockOIDC) authorizeTokenString(tokenString string, rw http.ResponseWriter) (*jwt.Token, bool) {
	token, err := m.Keypair.VerifyJWT(tokenString)
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

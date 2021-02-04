package mockoidc

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
)

func TestAuthorizeHandler(t *testing.T) {
	keypair, _ := RandomKeypair(2048)
	m, _ := NewServer(keypair.PrivateKey)

	data := url.Values{}
	data.Set("scope", "openid email profile")
	data.Set("response_type", "code")
	data.Set("redirect_uri", "example.com")
	data.Set("state", "testState")
	data.Set("client_id", m.ClientID)
	assert.HTTPError(t, m.Authorize, http.MethodGet, AuthorizeEndpoint, nil)

	// valid request
	assert.HTTPStatusCode(t, m.Authorize, http.MethodGet, AuthorizeEndpoint, data, 302)

	// Bad client ID
	data.Set("client_id", "wrong_id")
	assert.HTTPStatusCode(t, m.Authorize, http.MethodGet, AuthorizeEndpoint, data, 401)
	assert.HTTPBodyContains(t, m.Authorize, http.MethodGet, AuthorizeEndpoint, data, invalidClient)

	// Missing form value -- scope
	for key, _ := range data {
		newData, _ := url.ParseQuery(data.Encode())
		newData.Del(key)
		assert.HTTPStatusCode(t, m.Authorize, http.MethodGet, AuthorizeEndpoint, newData, 400)
		assert.HTTPBodyContains(t, m.Authorize, http.MethodGet, AuthorizeEndpoint, newData, invalidRequest)
	}
}

func TestAccessTokenRequest(t *testing.T) {
	keypair, _ := RandomKeypair(2048)
	m, _ := NewServer(keypair.PrivateKey)
	session, _ := m.SessionStore.NewSession("sessionScope", "sessionStrate", "sessionNonce", DefaultUser())

	assert.HTTPError(t, m.Token, http.MethodPost, TokenEndpoint, nil)

	data := url.Values{}
	data.Set("client_id", m.ClientID)
	data.Set("client_secret", m.ClientSecret)
	data.Set("code", session.SessionID)
	data.Set("grant_type", "authorization_code")

	// all values must be provided
	for key, _ := range data {
		newData, _ := url.ParseQuery(data.Encode())
		newData.Del(key)
		rr := testResponse(t, TokenEndpoint, m.Token, http.MethodPost, newData)
		assert.GreaterOrEqualf(t, rr.Code, 400, "Should be error but was %d, even though %s is missing", rr.Code, key)
		body, _ := ioutil.ReadAll(rr.Body)
		assert.Containsf(t, string(body), invalidRequest, "Should be %s, but was not", invalidRequest)
	}

	// wrong values won't work
	for key, _ := range data {
		newData, _ := url.ParseQuery(data.Encode())
		newData.Set(key, "This is wrong")
		rr := testResponse(t, TokenEndpoint, m.Token, http.MethodPost, newData)
		assert.GreaterOrEqualf(t, rr.Code, 400, "Should be error but was not, even though %s is an invalid value", key)
	}

	// good request; check responses
	rr := testResponse(t, TokenEndpoint, m.Token, http.MethodPost, data)
	assert.Equal(t, rr.Code, 200)

	var target *tokenResponse
	assert.NoError(t, getJSON(rr, &target))
	assert.NotEmpty(t, target.AccessToken)
	assert.NotEmpty(t, target.IDToken)
	assert.NotEmpty(t, target.RefreshToken)
	assert.NotEmpty(t, target.TokenType)
	assert.NotEmpty(t, target.ExpiresIn)

	var tknType *jwt.Token
	for _, tStr := range []string{target.AccessToken, target.RefreshToken, target.IDToken} {
		token, err := m.Keypair.VerifyJWT(tStr)
		assert.NoError(t, err)
		assert.IsType(t, tknType, token)
	}
	// TODO: validate returned tokens??
}

func TestRefreshTokenRequest(t *testing.T) {
	keypair, _ := RandomKeypair(2048)
	m, _ := NewServer(keypair.PrivateKey)
	session, _ := m.SessionStore.NewSession("sessionScope", "sessionStrate", "sessionNonce", DefaultUser())
	refreshToken, _ := session.RefreshToken(m.Config(), m.Keypair, m.Now())

	assert.HTTPError(t, m.Token, http.MethodPost, TokenEndpoint, nil)

	data := url.Values{}
	data.Set("client_id", m.ClientID)
	data.Set("client_secret", m.ClientSecret)
	data.Set("refresh_token", refreshToken)
	data.Set("grant_type", "refresh_token")

	// all values must be provided
	for key, _ := range data {
		newData, _ := url.ParseQuery(data.Encode())
		newData.Del(key)
		rr := testResponse(t, TokenEndpoint, m.Token, http.MethodPost, newData)
		assert.GreaterOrEqualf(t, rr.Code, 400, "Should be error but was %d, even though %s is missing", rr.Code, key)
		body, _ := ioutil.ReadAll(rr.Body)
		assert.Containsf(t, string(body), invalidRequest, "Should be %s, but was not", invalidRequest)
	}

	// wrong values won't work
	for key, _ := range data {
		newData, _ := url.ParseQuery(data.Encode())
		newData.Set(key, "This is wrong")
		rr := testResponse(t, TokenEndpoint, m.Token, http.MethodPost, newData)
		assert.GreaterOrEqualf(t, rr.Code, 400, "Should be error but was not, even though %s is an invalid value", key)
	}

	// good request; check responses
	rr := testResponse(t, TokenEndpoint, m.Token, http.MethodPost, data)
	assert.Equal(t, 200, rr.Code)
	body, _ := ioutil.ReadAll(rr.Body)
	assert.Contains(t, string(body), "refresh_token")

	refreshToken, _ = session.RefreshToken(m.Config(), m.Keypair, m.Now().Add(time.Hour*time.Duration(-24)))
	data.Set("refresh_token", refreshToken)
	rr = testResponse(t, TokenEndpoint, m.Token, http.MethodPost, data)
	assert.Equal(t, 401, rr.Code)
	body, _ = ioutil.ReadAll(rr.Body)
	assert.Contains(t, string(body), invalidRequest)
	// var target *tokenResponse
	// assert.NoError(t, getJSON(rr, &target))
	// assert.NotEmpty(t, target.AccessToken)
	// assert.NotEmpty(t, target.IDToken)
	// assert.NotEmpty(t, target.RefreshToken)
	// assert.NotEmpty(t, target.TokenType)
	// assert.NotEmpty(t, target.ExpiresIn)

	// var tknType *jwt.Token
	// for _, tStr := range []string{target.AccessToken, target.RefreshToken, target.IDToken} {
	// 	token, err := m.Keypair.VerifyJWT(tStr)
	// 	assert.NoError(t, err)
	// 	assert.IsType(t, tknType, token)
	// }
}

func TestMockOIDC_Discovery(t *testing.T) {
	m := &MockOIDC{
		Server: &http.Server{
			Addr: "127.0.0.1:8080",
		},
	}
	recorder := httptest.NewRecorder()
	m.Discovery(recorder, &http.Request{})

	oidcCfg := make(map[string]interface{})
	err := getJSON(recorder, &oidcCfg)
	assert.NoError(t, err)

	assert.Equal(t, oidcCfg["issuer"], m.Issuer())
	assert.Equal(t, oidcCfg["authorization_endpoint"], m.Issuer()+AuthorizeEndpoint)
	assert.Equal(t, oidcCfg["token_endpoint"], m.Issuer()+TokenEndpoint)
	assert.Equal(t, oidcCfg["userinfo_endpoint"], m.Issuer()+UserinfoEndpoint)
	assert.Equal(t, oidcCfg["jwks_uri"], m.Issuer()+JWKSEndpoint)
}

func getJSON(res *httptest.ResponseRecorder, target interface{}) error {
	return json.NewDecoder(res.Body).Decode(target)
}

func testResponse(t *testing.T, endpoint string, handler http.HandlerFunc,
	method string, values url.Values) *httptest.ResponseRecorder {

	rr := httptest.NewRecorder()
	req, err := http.NewRequest(method, endpoint, strings.NewReader(values.Encode()))
	assert.NoError(t, err)

	if method == http.MethodPost {
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Add("Content-Length", strconv.Itoa(len(values.Encode())))
	}
	handler(rr, req)
	return rr
}

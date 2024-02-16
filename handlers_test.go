package mockoidc_test

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

	"github.com/oauth2-proxy/mockoidc"
	"github.com/stretchr/testify/assert"
)

func TestMockOIDC_Authorize(t *testing.T) {
	m, err := mockoidc.NewServer(nil)
	assert.NoError(t, err)

	data := url.Values{}
	data.Set("scope", "openid email profile")
	data.Set("response_type", "code")
	data.Set("redirect_uri", "example.com")
	data.Set("state", "testState")
	data.Set("client_id", m.ClientID)
	data.Set("code_challenge", "somehash")
	data.Set("code_challenge_method", "S256")
	assert.HTTPError(t, m.Authorize, http.MethodGet, m.EndpointConfig.AuthorizationEndpoint, nil)

	// valid request
	assert.HTTPStatusCode(t, m.Authorize, http.MethodGet,
		m.EndpointConfig.AuthorizationEndpoint, data, http.StatusFound)

	// Bad client ID
	data.Set("client_id", "wrong_id")
	assert.HTTPStatusCode(t, m.Authorize, http.MethodGet,
		m.EndpointConfig.AuthorizationEndpoint, data, http.StatusUnauthorized)
	assert.HTTPBodyContains(t, m.Authorize, http.MethodGet,
		m.EndpointConfig.AuthorizationEndpoint, data, mockoidc.InvalidClient)

	// Bad code challenge method
	data.Set("client_id", m.ClientID)
	data.Set("code_challenge_method", "does not exist")
	assert.HTTPStatusCode(t, m.Authorize, http.MethodGet,
		m.EndpointConfig.AuthorizationEndpoint, data, http.StatusBadRequest)
	assert.HTTPBodyContains(t, m.Authorize, http.MethodGet,
		m.EndpointConfig.AuthorizationEndpoint, data, mockoidc.InvalidRequest)

	// Missing required form values
	for key := range data {
		if key == "code_challenge" || key == "code_challenge_method" {
			// Skip not required fields
			continue
		}

		t.Run(key, func(t *testing.T) {
			badData, _ := url.ParseQuery(data.Encode())
			badData.Del(key)

			assert.HTTPStatusCode(t, m.Authorize, http.MethodGet,
				m.EndpointConfig.AuthorizationEndpoint, badData, http.StatusBadRequest)
			assert.HTTPBodyContains(t, m.Authorize, http.MethodGet,
				m.EndpointConfig.AuthorizationEndpoint, badData, mockoidc.InvalidRequest)
		})
	}
}

func TestMockOIDC_Token_CodeGrant(t *testing.T) {
	m, err := mockoidc.NewServer(nil)
	assert.NoError(t, err)

	session, _ := m.SessionStore.NewSession(
		"openid email profile", "nonce", mockoidc.DefaultUser(), "", "")

	assert.HTTPError(t, m.Token, http.MethodPost, m.EndpointConfig.TokenEndpoint, nil)

	data := url.Values{}
	data.Set("client_id", m.ClientID)
	data.Set("client_secret", m.ClientSecret)
	data.Set("code", session.SessionID)
	data.Set("grant_type", "authorization_code")

	// Missing parameters result in BadRequest
	for key := range data {
		t.Run(key, func(t *testing.T) {
			badData, _ := url.ParseQuery(data.Encode())
			badData.Del(key)

			rr := testResponse(t, m.EndpointConfig.TokenEndpoint, m.Token, http.MethodPost, badData)
			assert.Equal(t, http.StatusBadRequest, rr.Code)

			body, err := ioutil.ReadAll(rr.Body)
			assert.NoError(t, err)
			assert.Contains(t, string(body), mockoidc.InvalidRequest)
		})
	}

	// wrong values won't work
	for key := range data {
		t.Run(key, func(t *testing.T) {
			badData, err := url.ParseQuery(data.Encode())
			assert.NoError(t, err)

			badData.Set(key, "WRONG")
			rr := testResponse(t, m.EndpointConfig.TokenEndpoint, m.Token, http.MethodPost, badData)
			if key == "grant_type" {
				assert.Equal(t, http.StatusBadRequest, rr.Code)
			} else {
				assert.Equal(t, http.StatusUnauthorized, rr.Code)
			}
		})
	}

	// good request; check responses
	rr := testResponse(t, m.EndpointConfig.TokenEndpoint, m.Token, http.MethodPost, data)
	assert.Equal(t, http.StatusOK, rr.Code)

	tokenResp := make(map[string]interface{})
	err = getJSON(rr, &tokenResp)
	assert.NoError(t, err)

	assert.Contains(t, tokenResp, "access_token")
	assert.Contains(t, tokenResp, "id_token")
	assert.Contains(t, tokenResp, "refresh_token")
	assert.Contains(t, tokenResp, "token_type")
	assert.Contains(t, tokenResp, "expires_in")

	for _, key := range []string{
		"access_token",
		"refresh_token",
		"id_token",
	} {
		t.Run(key, func(t *testing.T) {
			_, err := m.Keypair.VerifyJWT(tokenResp[key].(string), m.Now)
			assert.NoError(t, err)
		})
	}

	// duplicate attempts are rejects
	rrDup := testResponse(t, m.EndpointConfig.TokenEndpoint, m.Token, http.MethodPost, data)
	assert.Equal(t, http.StatusUnauthorized, rrDup.Code)
}

func TestMockOIDC_Token_CodeGrant_CodeChallengePlain(t *testing.T) {
	m, err := mockoidc.NewServer(nil)
	assert.NoError(t, err)

	codeChallenge, err := mockoidc.GenerateCodeChallenge(mockoidc.CodeChallengeMethodPlain, "sum")
	assert.NoError(t, err)
	session, _ := m.SessionStore.NewSession(
		"openid email profile", "nonce", mockoidc.DefaultUser(),
		codeChallenge, mockoidc.CodeChallengeMethodPlain)

	assert.HTTPError(t, m.Token, http.MethodPost, m.EndpointConfig.TokenEndpoint, nil)

	data := url.Values{}
	data.Set("client_id", m.ClientID)
	data.Set("client_secret", m.ClientSecret)
	data.Set("code", session.SessionID)
	data.Set("grant_type", "authorization_code")
	data.Set("code_verifier", "sum")

	// good request; good response
	rr := testResponse(t, m.EndpointConfig.TokenEndpoint, m.Token, http.MethodPost, data)
	assert.Equal(t, http.StatusOK, rr.Code)

	tokenResp := make(map[string]interface{})
	err = getJSON(rr, &tokenResp)
	assert.NoError(t, err)

	// bad request; no verifier provided
	badData, _ := url.ParseQuery(data.Encode())
	badData.Del("code_verifier")

	rr = testResponse(t, m.EndpointConfig.TokenEndpoint, m.Token, http.MethodPost, badData)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	body, err := ioutil.ReadAll(rr.Body)
	assert.NoError(t, err)
	assert.Contains(t, string(body), mockoidc.InvalidGrant)

	// bad request; bad verifier provided
	badData, _ = url.ParseQuery(data.Encode())
	badData.Set("code_verifier", "WRONG")

	rr = testResponse(t, m.EndpointConfig.TokenEndpoint, m.Token, http.MethodPost, badData)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	body, err = ioutil.ReadAll(rr.Body)
	assert.NoError(t, err)
	assert.Contains(t, string(body), mockoidc.InvalidGrant)
}

func TestMockOIDC_Token_CodeGrant_CodeChallengeHash(t *testing.T) {
	m, err := mockoidc.NewServer(nil)
	assert.NoError(t, err)

	codeChallenge, err := mockoidc.GenerateCodeChallenge(mockoidc.CodeChallengeMethodS256, "sum")
	assert.NoError(t, err)
	session, _ := m.SessionStore.NewSession(
		"openid email profile", "nonce", mockoidc.DefaultUser(),
		codeChallenge, mockoidc.CodeChallengeMethodS256)

	assert.HTTPError(t, m.Token, http.MethodPost, m.EndpointConfig.TokenEndpoint, nil)

	data := url.Values{}
	data.Set("client_id", m.ClientID)
	data.Set("client_secret", m.ClientSecret)
	data.Set("code", session.SessionID)
	data.Set("grant_type", "authorization_code")
	data.Set("code_verifier", "sum")

	// good request; good response
	rr := testResponse(t, m.EndpointConfig.TokenEndpoint, m.Token, http.MethodPost, data)
	assert.Equal(t, http.StatusOK, rr.Code)

	tokenResp := make(map[string]interface{})
	err = getJSON(rr, &tokenResp)
	assert.NoError(t, err)

	// bad request; no verifier provided
	badData, _ := url.ParseQuery(data.Encode())
	badData.Del("code_verifier")

	rr = testResponse(t, m.EndpointConfig.TokenEndpoint, m.Token, http.MethodPost, badData)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	body, err := ioutil.ReadAll(rr.Body)
	assert.NoError(t, err)
	assert.Contains(t, string(body), mockoidc.InvalidGrant)

	// bad request; bad verifier provided
	badData, _ = url.ParseQuery(data.Encode())
	badData.Set("code_verifier", "WRONG")

	rr = testResponse(t, m.EndpointConfig.TokenEndpoint, m.Token, http.MethodPost, badData)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	body, err = ioutil.ReadAll(rr.Body)
	assert.NoError(t, err)
	assert.Contains(t, string(body), mockoidc.InvalidGrant)
}

func TestMockOIDC_Token_RefreshGrant(t *testing.T) {
	m, err := mockoidc.NewServer(nil)
	assert.NoError(t, err)

	session, _ := m.SessionStore.NewSession(
		"openid email profile", "sessionNonce", mockoidc.DefaultUser(), "", "")
	refreshToken, _ := session.RefreshToken(m.Config(), m.Keypair, m.Now())

	assert.HTTPError(t, m.Token, http.MethodPost, m.EndpointConfig.TokenEndpoint, nil)

	data := url.Values{}
	data.Set("client_id", m.ClientID)
	data.Set("client_secret", m.ClientSecret)
	data.Set("refresh_token", refreshToken)
	data.Set("grant_type", "refresh_token")

	// good request; check responses
	rr := testResponse(t, m.EndpointConfig.TokenEndpoint, m.Token, http.MethodPost, data)
	assert.Equal(t, http.StatusOK, rr.Code)

	tokenResp := make(map[string]interface{})
	err = getJSON(rr, &tokenResp)
	assert.NoError(t, err)

	assert.Contains(t, tokenResp, "access_token")
	assert.Contains(t, tokenResp, "id_token")
	assert.Contains(t, tokenResp, "refresh_token")
	assert.Contains(t, tokenResp, "token_type")
	assert.Contains(t, tokenResp, "expires_in")

	for _, key := range []string{
		"access_token",
		"refresh_token",
		"id_token",
	} {
		t.Run(key, func(t *testing.T) {
			_, err := m.Keypair.VerifyJWT(tokenResp[key].(string), m.Now)
			assert.NoError(t, err)
		})
	}

	// expired refresh token
	expiredToken, err := session.RefreshToken(
		m.Config(), m.Keypair, m.Now().Add(time.Hour*time.Duration(-24)))
	assert.NoError(t, err)

	data.Set("refresh_token", expiredToken)

	rr = testResponse(t, m.EndpointConfig.TokenEndpoint, m.Token, http.MethodPost, data)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	body, err := ioutil.ReadAll(rr.Body)
	assert.NoError(t, err)
	assert.Contains(t, string(body), mockoidc.InvalidRequest)
}

func TestMockOIDC_Discovery(t *testing.T) {
	m := &mockoidc.MockOIDC{
		Server: &http.Server{
			Addr: "127.0.0.1:8080",
		},
		CodeChallengeMethodsSupported: []string{"some_random_value"},
	}
	recorder := httptest.NewRecorder()
	m.Discovery(recorder, &http.Request{})

	oidcCfg := make(map[string]interface{})
	err := getJSON(recorder, &oidcCfg)
	assert.NoError(t, err)

	assert.Equal(t, oidcCfg["issuer"], m.Issuer())
	assert.Equal(t, oidcCfg["authorization_endpoint"], m.AuthorizationEndpoint())
	assert.Equal(t, oidcCfg["token_endpoint"], m.TokenEndpoint())
	assert.Equal(t, oidcCfg["userinfo_endpoint"], m.UserinfoEndpoint())
	assert.Equal(t, oidcCfg["jwks_uri"], m.JWKSEndpoint())
	assert.ElementsMatch(t, oidcCfg["code_challenge_methods_supported"], m.CodeChallengeMethodsSupported)
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

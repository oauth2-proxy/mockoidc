package mockoidc_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/oauth2-proxy/mockoidc"
	"github.com/stretchr/testify/assert"
)

const TestNow = 1234567890

// A custom client that doesn't automatically follow redirects
var httpClient = &http.Client{
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func TestRun(t *testing.T) {
	setTime()
	defer resetTime()

	m, err := mockoidc.Run()
	assert.NoError(t, err)
	defer m.Shutdown()

	// ************************************************************************
	// Stage 0: Get Discovery documents
	// ************************************************************************
	discoveryReq, err := http.NewRequest(http.MethodGet, m.DiscoveryEndpoint(), nil)
	assert.NoError(t, err)

	resp, err := httpClient.Do(discoveryReq)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	jwksReq, err := http.NewRequest(http.MethodGet, m.JWKSEndpoint(), nil)
	assert.NoError(t, err)

	resp, err = httpClient.Do(jwksReq)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	config := m.Config()

	// ************************************************************************
	// Stage 1: Emulate client to IdP request
	// ************************************************************************
	const (
		state = "abcdef1234567890"
		nonce = "0987654321fedcba"
		code  = "asdflkjh12340987"
	)
	authorizeQuery := url.Values{}
	authorizeQuery.Set("client_id", config.ClientID)
	authorizeQuery.Set("scope", "openid email profile groups")
	authorizeQuery.Set("response_type", "code")
	authorizeQuery.Set("redirect_uri", "http://127.0.0.1/oauth2/callback")
	authorizeQuery.Set("state", state)
	authorizeQuery.Set("nonce", nonce)

	codeVerifier := "sum"
	challenge, err := mockoidc.GenerateCodeChallenge(mockoidc.CodeChallengeMethodS256, codeVerifier)
	assert.NoError(t, err)
	authorizeQuery.Set("code_challenge", challenge)
	authorizeQuery.Set("code_challenge_method", mockoidc.CodeChallengeMethodS256)

	authorizeURL, err := url.Parse(m.AuthorizationEndpoint())
	assert.NoError(t, err)
	authorizeURL.RawQuery = authorizeQuery.Encode()

	authorizeReq, err := http.NewRequest(http.MethodGet, authorizeURL.String(), nil)
	assert.NoError(t, err)

	m.QueueCode(code)
	resp, err = httpClient.Do(authorizeReq)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusFound, resp.StatusCode)

	appRedirect, err := url.Parse(resp.Header.Get("Location"))
	assert.NoError(t, err)
	assert.Equal(t, code, appRedirect.Query().Get("code"))
	assert.Equal(t, state, appRedirect.Query().Get("state"))

	// ************************************************************************
	// Stage 2: Emulate appRedirect handling token endpoint call
	// ************************************************************************
	tokenForm := url.Values{}
	tokenForm.Set("client_id", config.ClientID)
	tokenForm.Set("client_secret", config.ClientSecret)
	tokenForm.Set("grant_type", "authorization_code")
	tokenForm.Set("code", appRedirect.Query().Get("code"))
	tokenForm.Set("code_verifier", codeVerifier)

	tokenReq, err := http.NewRequest(
		http.MethodPost, m.TokenEndpoint(), bytes.NewBufferString(tokenForm.Encode()))
	assert.NoError(t, err)
	tokenReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err = httpClient.Do(tokenReq)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	assert.NoError(t, err)

	tokens := make(map[string]interface{})
	err = json.Unmarshal(body, &tokens)
	assert.NoError(t, err)

	_, err = m.Keypair.VerifyJWT(tokens["access_token"].(string), m.Now)
	assert.NoError(t, err)
	_, err = m.Keypair.VerifyJWT(tokens["refresh_token"].(string), m.Now)
	assert.NoError(t, err)
	idToken, err := m.Keypair.VerifyJWT(tokens["id_token"].(string), m.Now)
	assert.NoError(t, err)

	// The nonce we set initially is in our ID Token
	claims, ok := idToken.Claims.(jwt.MapClaims)
	assert.True(t, ok)
	assert.Equal(t, nonce, claims["nonce"])

	// ************************************************************************
	// Stage 3: Use the Access Token for a Userinfo call
	// ************************************************************************
	userinfoReq, err := http.NewRequest(http.MethodGet, m.UserinfoEndpoint(), nil)
	assert.NoError(t, err)
	userinfoReq.Header.Add("Authorization", fmt.Sprintf("Bearer %s", tokens["id_token"]))

	resp, err = httpClient.Do(userinfoReq)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// ************************************************************************
	// Stage 4: Expired Tokens don't work
	// ************************************************************************
	m.FastForward(config.AccessTTL + 1)

	expiredReq, err := http.NewRequest(http.MethodGet, m.UserinfoEndpoint(), nil)
	assert.NoError(t, err)
	userinfoReq.Header.Add("Authorization", fmt.Sprintf("Bearer %s", tokens["id_token"]))

	resp, err = httpClient.Do(expiredReq)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// ************************************************************************
	// Stage 5: We can refresh them
	// ************************************************************************
	refreshForm := url.Values{}
	refreshForm.Set("client_id", config.ClientID)
	refreshForm.Set("client_secret", config.ClientSecret)
	refreshForm.Set("grant_type", "refresh_token")
	refreshForm.Set("refresh_token", tokens["refresh_token"].(string))

	refreshReq, err := http.NewRequest(
		http.MethodPost, m.TokenEndpoint(), bytes.NewBufferString(refreshForm.Encode()))
	assert.NoError(t, err)
	refreshReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err = httpClient.Do(refreshReq)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	defer resp.Body.Close()
	refreshBody, err := ioutil.ReadAll(resp.Body)
	assert.NoError(t, err)

	refreshedTokens := make(map[string]interface{})
	err = json.Unmarshal(refreshBody, &refreshedTokens)
	assert.NoError(t, err)

	_, err = m.Keypair.VerifyJWT(refreshedTokens["access_token"].(string), m.Now)
	assert.NoError(t, err)
	_, err = m.Keypair.VerifyJWT(refreshedTokens["refresh_token"].(string), m.Now)
	assert.NoError(t, err)
	refreshedIDToken, err := m.Keypair.VerifyJWT(refreshedTokens["id_token"].(string), m.Now)
	assert.NoError(t, err)

	// The nonce we set initially is STILL in our ID Token
	refreshedClaims, ok := refreshedIDToken.Claims.(jwt.MapClaims)
	assert.True(t, ok)
	assert.Equal(t, nonce, refreshedClaims["nonce"])

	// ************************************************************************
	// Stage 6: Access Token works again
	// ************************************************************************
	userinfoReq2, err := http.NewRequest(http.MethodGet, m.UserinfoEndpoint(), nil)
	assert.NoError(t, err)
	userinfoReq2.Header.Add("Authorization",
		fmt.Sprintf("Bearer %s", refreshedTokens["id_token"]))

	resp, err = httpClient.Do(userinfoReq2)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// ************************************************************************
	// Stage 7: Refresh Tokens expire and won't refresh
	// ************************************************************************
	m.FastForward(config.RefreshTTL)

	refreshForm2 := url.Values{}
	refreshForm2.Set("client_id", config.ClientID)
	refreshForm2.Set("client_secret", config.ClientSecret)
	refreshForm2.Set("grant_type", "refresh_token")
	refreshForm2.Set("refresh_token", tokens["refresh_token"].(string))

	refreshReq2, err := http.NewRequest(
		http.MethodPost, m.TokenEndpoint(), bytes.NewBufferString(tokenForm.Encode()))
	assert.NoError(t, err)
	refreshReq2.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err = httpClient.Do(refreshReq2)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestMockOIDC_Config(t *testing.T) {
	m, err := mockoidc.Run()
	assert.NoError(t, err)
	defer m.Shutdown()

	cfg := m.Config()
	assert.Equal(t, m.ClientID, cfg.ClientID)
	assert.Equal(t, m.ClientSecret, cfg.ClientSecret)
	assert.Equal(t, m.Issuer(), cfg.Issuer)
	assert.Equal(t, m.AccessTTL, cfg.AccessTTL)
	assert.Equal(t, m.RefreshTTL, cfg.RefreshTTL)
	assert.Equal(t, m.CodeChallengeMethodsSupported, cfg.CodeChallengeMethodsSupported)
}

func TestMockOIDC_QueueError(t *testing.T) {
	m, err := mockoidc.Run()
	assert.NoError(t, err)
	defer m.Shutdown()

	type handlerError struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}

	m.QueueError(&mockoidc.ServerError{
		Code:        http.StatusInternalServerError,
		Error:       mockoidc.InternalServerError,
		Description: "Discovery Error",
	})

	m.QueueError(&mockoidc.ServerError{
		Code:        http.StatusBadRequest,
		Error:       mockoidc.InvalidRequest,
		Description: "Authorize Error",
	})

	// First Queued Error
	discoveryReq, err := http.NewRequest(http.MethodGet, m.DiscoveryEndpoint(), nil)
	assert.NoError(t, err)

	resp, err := httpClient.Do(discoveryReq)
	assert.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)

	var discoveryResp handlerError
	err = json.NewDecoder(resp.Body).Decode(&discoveryResp)
	assert.NoError(t, err)
	assert.Equal(t, "Discovery Error", discoveryResp.Description)

	// Second Queued Error
	authorizeReq, err := http.NewRequest(http.MethodGet, m.AuthorizationEndpoint(), nil)
	assert.NoError(t, err)

	resp, err = httpClient.Do(authorizeReq)
	assert.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var authorizeResp handlerError
	err = json.NewDecoder(resp.Body).Decode(&authorizeResp)
	assert.NoError(t, err)
	assert.Equal(t, "Authorize Error", authorizeResp.Description)

	// No Errors Queued
	jwksReq, err := http.NewRequest(http.MethodGet, m.JWKSEndpoint(), nil)
	assert.NoError(t, err)

	resp, err = httpClient.Do(jwksReq)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestMockOIDC_AddMiddleware(t *testing.T) {
	before := 0
	after := 0
	flagger := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			before = before + 1
			next.ServeHTTP(rw, req)
			after = after + 1
		})
	}

	m, err := mockoidc.NewServer(nil)
	assert.NoError(t, err)

	const chains = 5
	for i := 0; i < chains; i++ {
		err = m.AddMiddleware(flagger)
		assert.NoError(t, err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)

	err = m.Start(ln, nil)
	assert.NoError(t, err)
	defer m.Shutdown()

	// middleware not run
	assert.Equal(t, 0, before)
	assert.Equal(t, 0, after)

	req, err := http.NewRequest(http.MethodGet, m.DiscoveryEndpoint(), nil)
	assert.NoError(t, err)
	_, err = httpClient.Do(req)
	assert.NoError(t, err)

	// middleware run around the request
	assert.Equal(t, chains, before)
	assert.Equal(t, chains, after)

	// no new middleware allowed after starting
	err = m.AddMiddleware(flagger)
	assert.Error(t, err)
}

func TestMockOIDC_FastForward(t *testing.T) {
	setTime()
	defer resetTime()

	m := &mockoidc.MockOIDC{}

	ff1 := m.FastForward(time.Duration(123))
	assert.Equal(t, time.Duration(123), ff1)
	assert.Equal(t, mockoidc.NowFunc().Add(time.Duration(123)), m.Now())

	ff2 := m.FastForward(time.Duration(456))
	assert.Equal(t, time.Duration(579), ff2)
	assert.Equal(t, mockoidc.NowFunc().Add(time.Duration(579)), m.Now())
}

func setTime() {
	mockoidc.NowFunc = func() time.Time {
		return time.Unix(TestNow, 0)
	}
	jwt.WithTimeFunc(func() time.Time {
		return time.Unix(TestNow, 0)
	})
}

func resetTime() {
	mockoidc.NowFunc = time.Now
	jwt.WithTimeFunc(time.Now)
}

package mockoidc

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// NowFunc is an overrideable version of `time.Now`. Tests that need to
// manipulate time can use their own `func() Time` function.
var NowFunc = time.Now

// MockOIDC is a minimal OIDC server for use in OIDC authentication
// integration testing.
type MockOIDC struct {
	ClientID     string
	ClientSecret string

	AccessTTL  time.Duration
	RefreshTTL time.Duration

	CodeChallengeMethodsSupported []string

	// Normally, these would be private. Expose them publicly for
	// power users.
	Server       *http.Server
	Keypair      *Keypair
	SessionStore *SessionStore
	UserQueue    *UserQueue
	ErrorQueue   *ErrorQueue

	tlsConfig   *tls.Config
	middleware  []func(http.Handler) http.Handler
	fastForward time.Duration

	EndpointConfig EndpointConfig
}

// Config gives the various settings MockOIDC starts with that a test
// application server would need to be configured with.
type Config struct {
	ClientID     string
	ClientSecret string
	Issuer       string

	AccessTTL  time.Duration
	RefreshTTL time.Duration

	CodeChallengeMethodsSupported []string
}

// NewServer configures a new MockOIDC that isn't started. An existing
// rsa.PrivateKey can be passed for token signing operations in case
// the default Keypair isn't desired.
func NewServer(key *rsa.PrivateKey) (*MockOIDC, error) {
	clientID, err := randomNonce(24)
	if err != nil {
		return nil, err
	}
	clientSecret, err := randomNonce(24)
	if err != nil {
		return nil, err
	}
	keypair, err := NewKeypair(key)
	if err != nil {
		return nil, err
	}

	ecfg := EndpointConfig{}
	ecfg.Defaults()

	return &MockOIDC{
		ClientID:                      clientID,
		ClientSecret:                  clientSecret,
		AccessTTL:                     time.Duration(10) * time.Minute,
		RefreshTTL:                    time.Duration(60) * time.Minute,
		CodeChallengeMethodsSupported: []string{"plain", "S256"},
		Keypair:                       keypair,
		SessionStore:                  NewSessionStore(),
		UserQueue:                     &UserQueue{},
		ErrorQueue:                    &ErrorQueue{},
		EndpointConfig:                ecfg,
	}, nil
}

// Run creates a default MockOIDC server and starts it
func Run() (*MockOIDC, error) {
	return RunTLS(nil)
}

// RunTLS creates a default MockOIDC server and starts it. It takes a
// tester configured tls.Config for TLS support.
func RunTLS(cfg *tls.Config) (*MockOIDC, error) {
	m, err := NewServer(nil)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	return m, m.Start(ln, cfg)
}

// Start starts the MockOIDC server in its own Goroutine on the provided
// net.Listener. In generic `Run`, this defaults to `127.0.0.1:0`
func (m *MockOIDC) Start(ln net.Listener, cfg *tls.Config) error {
	if m.Server != nil {
		return errors.New("server already started")
	}

	var pathOf = func(s string) string {
		u, err := url.Parse(s)
		if err != nil {
			return s
		}
		return u.Path
	}

	handler := http.NewServeMux()
	handler.Handle(pathOf(m.EndpointConfig.AuthorizationEndpoint), m.chainMiddleware(m.Authorize))
	handler.Handle(pathOf(m.EndpointConfig.TokenEndpoint), m.chainMiddleware(m.Token))
	handler.Handle(pathOf(m.EndpointConfig.UserinfoEndpoint), m.chainMiddleware(m.Userinfo))
	handler.Handle(pathOf(m.EndpointConfig.JWKSEndpoint), m.chainMiddleware(m.JWKS))
	handler.Handle(pathOf(m.EndpointConfig.DiscoveryEndpoint), m.chainMiddleware(m.Discovery))

	m.Server = &http.Server{
		Addr:      ln.Addr().String(),
		Handler:   handler,
		TLSConfig: cfg,
	}
	// Track this to know if we are https
	m.tlsConfig = cfg

	go func() {
		err := m.Server.Serve(ln)
		if err != nil && err != http.ErrServerClosed {
			panic(err)
		}
	}()

	return nil
}

// Shutdown stops the MockOIDC server. Use this to cleanup test runs.
func (m *MockOIDC) Shutdown() error {
	return m.Server.Shutdown(context.Background())
}

func (m *MockOIDC) AddMiddleware(mw func(http.Handler) http.Handler) error {
	if m.Server != nil {
		return errors.New("server already started")
	}

	m.middleware = append(m.middleware, mw)
	return nil
}

// Config returns the Config with options a connection application or unit
// tests need to be aware of.
func (m *MockOIDC) Config() *Config {
	return &Config{
		ClientID:                      m.ClientID,
		ClientSecret:                  m.ClientSecret,
		Issuer:                        m.Issuer(),
		CodeChallengeMethodsSupported: m.CodeChallengeMethodsSupported,
		AccessTTL:                     m.AccessTTL,
		RefreshTTL:                    m.RefreshTTL,
	}
}

// QueueUser allows adding mock User objects to the authentication queue.
// Calls to the `authorization_endpoint` will pop these mock User objects
// off the queue and create a session with them.
func (m *MockOIDC) QueueUser(user User) {
	m.UserQueue.Push(user)
}

// QueueCode allows adding mock code strings to the authentication queue.
// Calls to the `authorization_endpoint` will pop these code strings
// off the queue and create a session with them and return them as the
// code parameter in the response.
func (m *MockOIDC) QueueCode(code string) {
	m.SessionStore.CodeQueue.Push(code)
}

// QueueError allows queueing arbitrary errors for the next handler calls
// to return.
func (m *MockOIDC) QueueError(se *ServerError) {
	m.ErrorQueue.Push(se)
}

// FastForward moves the MockOIDC's internal view of time forward.
// Use this to test token expirations in your tests.
func (m *MockOIDC) FastForward(d time.Duration) time.Duration {
	m.fastForward = m.fastForward + d
	return m.fastForward
}

// Now is what MockOIDC thinks time.Now is
func (m *MockOIDC) Now() time.Time {
	return NowFunc().Add(m.fastForward)
}

// Addr returns the server address (if started)
func (m *MockOIDC) Addr() string {
	if m.Server == nil {
		return ""
	}
	proto := "http"
	if m.tlsConfig != nil {
		proto = "https"
	}
	return fmt.Sprintf("%s://%s", proto, m.Server.Addr)
}

// applyBase adds a the server scheme and host to the given url, unless it is already absolute.
func (m *MockOIDC) applyBase(u string) string {
	if strings.Contains(u, "://") {
		return u
	}

	return m.Addr() + u
}

// Issuer returns the OIDC Issuer that will be in `iss` token claims
func (m *MockOIDC) Issuer() string {
	if m.Server == nil {
		return ""
	}
	return m.applyBase(m.EndpointConfig.IssuerBase)
}

// DiscoveryEndpoint returns the full `/.well-known/openid-configuration` URL
func (m *MockOIDC) DiscoveryEndpoint() string {
	if m.Server == nil {
		return ""
	}
	return m.applyBase(m.EndpointConfig.DiscoveryEndpoint)
}

// AuthorizationEndpoint returns the OIDC `authorization_endpoint`
func (m *MockOIDC) AuthorizationEndpoint() string {
	if m.Server == nil {
		return ""
	}
	return m.applyBase(m.EndpointConfig.AuthorizationEndpoint)
}

// TokenEndpoint returns the OIDC `token_endpoint`
func (m *MockOIDC) TokenEndpoint() string {
	if m.Server == nil {
		return ""
	}
	return m.applyBase(m.EndpointConfig.TokenEndpoint)
}

// UserinfoEndpoint returns the OIDC `userinfo_endpoint`
func (m *MockOIDC) UserinfoEndpoint() string {
	if m.Server == nil {
		return ""
	}
	return m.applyBase(m.EndpointConfig.UserinfoEndpoint)
}

// JWKSEndpoint returns the OIDC `jwks_uri`
func (m *MockOIDC) JWKSEndpoint() string {
	if m.Server == nil {
		return ""
	}
	return m.applyBase(m.EndpointConfig.JWKSEndpoint)
}

func (m *MockOIDC) chainMiddleware(endpoint func(http.ResponseWriter, *http.Request)) http.Handler {
	chain := m.forceError(http.HandlerFunc(endpoint))
	for i := len(m.middleware) - 1; i >= 0; i-- {
		mw := m.middleware[i]
		chain = mw(chain)
	}
	return chain
}

func (m *MockOIDC) forceError(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if se := m.ErrorQueue.Pop(); se != nil {
			errorResponse(rw, se.Error, se.Description, se.Code)
		} else {
			next.ServeHTTP(rw, req)
		}
	})
}

package mockoidc

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
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

	// Normally, these would be private. Expose them publicly for
	// power users.
	Server       *http.Server
	Keypair      *Keypair
	SessionStore *SessionStore
	UserQueue    *UserQueue

	tlsConfig   *tls.Config
	fastForward time.Duration
}

// Config gives the various settings MockOIDC starts with that a test
// application server would need to be configured with.
type Config struct {
	ClientID     string
	ClientSecret string
	Issuer       string

	AccessTTL  time.Duration
	RefreshTTL time.Duration
}

// NewServer configures a new MockOIDC that isn't started. An existing
// rsa.PrivateKey can be passed for token signing operations in case
// randomly generating them on each test run is too compute intensive.
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

	return &MockOIDC{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		AccessTTL:    time.Duration(10) * time.Minute,
		RefreshTTL:   time.Duration(60) * time.Minute,
		Keypair:      keypair,
		SessionStore: NewSessionStore(),
		UserQueue:    &UserQueue{},
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

	handler := http.NewServeMux()
	handler.HandleFunc(AuthorizationEndpoint, m.Authorize)
	handler.HandleFunc(TokenEndpoint, m.Token)
	handler.HandleFunc(UserinfoEndpoint, m.Userinfo)
	handler.HandleFunc(JWKSEndpoint, m.JWKS)
	handler.HandleFunc(DiscoveryEndpoint, m.JWKS)

	m.Server = &http.Server{
		Addr:      ln.Addr().String(),
		Handler:   handler,
		TLSConfig: cfg,
	}
	//
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

// Config returns the Config with options a connection application or unit
// tests need to be aware of.
func (m *MockOIDC) Config() *Config {
	return &Config{
		ClientID:     m.ClientID,
		ClientSecret: m.ClientSecret,
		Issuer:       m.Issuer(),
		AccessTTL:    m.AccessTTL,
		RefreshTTL:   m.RefreshTTL,
	}
}

// QueueUser allows adding mock User objects to the authentication queue.
// Calls to the `authorization_endpoint` will pop these mock User objects
// off the queue and create a session with them.
func (m *MockOIDC) QueueUser(user *User) {
	m.UserQueue.Push(user)
}

// QueueCode allows adding mock code strings to the authentication queue.
// Calls to the `authorization_endpoint` will pop these code strings
// off the queue and create a session with them and return them as the
// code parameter in the response.
func (m *MockOIDC) QueueCode(code string) {
	m.SessionStore.CodeQueue.Push(code)
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

// Synchronize sets the jwt.TimeFunc to our mutated view of time
func (m *MockOIDC) Synchronize() {
	jwt.TimeFunc = m.Now
}

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

func (m *MockOIDC) Issuer() string {
	if m.Server == nil {
		return ""
	}
	return m.Addr() + IssuerBase
}

func (m *MockOIDC) DiscoveryEndpoint() string {
	if m.Server == nil {
		return ""
	}
	return m.Addr() + DiscoveryEndpoint
}

func (m *MockOIDC) AuthorizationEndpoint() string {
	if m.Server == nil {
		return ""
	}
	return m.Addr() + AuthorizationEndpoint
}

func (m *MockOIDC) TokenEndpoint() string {
	if m.Server == nil {
		return ""
	}
	return m.Addr() + TokenEndpoint
}

func (m *MockOIDC) UserinfoEndpoint() string {
	if m.Server == nil {
		return ""
	}
	return m.Addr() + UserinfoEndpoint
}

func (m *MockOIDC) JWKSEndpoint() string {
	if m.Server == nil {
		return ""
	}
	return m.Addr() + JWKSEndpoint
}

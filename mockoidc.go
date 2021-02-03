package mockoidc

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	authorizeEndpoint = "/authorize"
	tokenEndpoint     = "/token"
)

var NowFunc = time.Now

type MockOIDC struct {
	sync.Mutex

	ClientID     string
	ClientSecret string

	AccessTTL  time.Duration
	RefreshTTL time.Duration

	Keypair *Keypair

	server      *http.Server
	userQueue   []*User
	fastForward time.Duration
}

type Config struct {
	ClientID     string
	ClientSecret string
	Issuer       string

	AccessTTL  time.Duration
	RefreshTTL time.Duration
}

func NewServer(key *rsa.PrivateKey) (*MockOIDC, error) {
	clientID, err := nonce(24)
	if err != nil {
		return nil, err
	}
	clientSecret, err := nonce(24)
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
	}, nil
}

func Run() (*MockOIDC, error) {
	return RunTLS(nil)
}

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

func (m *MockOIDC) Start(ln net.Listener, cfg *tls.Config) error {
	if m.server != nil {
		return errors.New("server already started")
	}

	handler := http.NewServeMux()
	handler.HandleFunc(authorizeEndpoint, m.Authorize)

	m.server = &http.Server{
		Addr:      ln.Addr().String(),
		Handler:   handler,
		TLSConfig: cfg,
	}

	go func() {
		err := m.server.Serve(ln)
		if err != nil && err != http.ErrServerClosed {
			panic(err)
		}
	}()

	return nil
}

func (m *MockOIDC) Shutdown() error {
	return m.server.Shutdown(context.Background())
}

func (m *MockOIDC) Authorize(rw http.ResponseWriter, req *http.Request) {
	http.Redirect(rw, req, tokenEndpoint, http.StatusFound)
}

func (m *MockOIDC) Config() *Config {
	return &Config{
		ClientID:     m.ClientID,
		ClientSecret: m.ClientSecret,
		Issuer:       m.Issuer(),
		AccessTTL:    m.AccessTTL,
		RefreshTTL:   m.RefreshTTL,
	}
}

func (m *MockOIDC) Issuer() string {
	if m.server == nil {
		return ""
	}
	proto := "http"
	if m.server.TLSConfig != nil {
		proto = "https"
	}
	return fmt.Sprintf("%s://%s/", proto, m.server.Addr)
}

func (m *MockOIDC) QueueUser(user *User) {
	m.Lock()
	defer m.Unlock()

	m.userQueue = append(m.userQueue, user)
}

func (m *MockOIDC) FastForward(d time.Duration) {
	m.fastForward = m.fastForward + d
}

func (m *MockOIDC) Now() time.Time {
	return NowFunc().Add(m.fastForward)
}

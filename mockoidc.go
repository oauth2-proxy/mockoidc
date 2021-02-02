package mockoidc

import (
	"context"
	"net/http"
	"sync"
)

const (
	authorizeEndpoint = "/authorize"
	tokenEndpoint     = "/token"
)

type MockOIDC struct {
	sync.Mutex

	ClientID     string
	ClientSecret string

	server http.Server
}

func NewMockOIDC() (*MockOIDC, error) {
	clientID, err := nonce(24)
	if err != nil {
		return nil, err
	}
	clientSecret, err := nonce(24)
	if err != nil {
		return nil, err
	}

	return &MockOIDC{
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}, nil
}

func Run() (*MockOIDC, error) {
	m, err := NewMockOIDC()
	if err != nil {
		return nil, err
	}
	// TODO: Random Port
	return m, m.Start("127.0.0.1:8000")
}

func (m *MockOIDC) Start(addr string) error {
	handler := http.NewServeMux()
	handler.HandleFunc(authorizeEndpoint, m.authorize)

	m.server = http.Server{
		Addr:    addr,
		Handler: handler,
	}

	go func() {
		err := m.server.ListenAndServe()
		if err != nil {
			// TODO: channel to return error?
			panic(err)
		}
	}()

	return nil
}

func (m *MockOIDC) Shutdown() error {
	return m.server.Shutdown(context.Background())
}

func (m *MockOIDC) authorize(rw http.ResponseWriter, req *http.Request) {
	http.Redirect(rw, req, tokenEndpoint, http.StatusFound)
}

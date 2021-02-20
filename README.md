# mockoidc

A Mock OpenID Connect Server for Authentication Unit and Integration Tests.

Created by @NickMeves and @egrif during the [Greenhouse Software](https://medium.com/in-the-weeds)
2021 Q1 Hack Day.

[![Go Report Card](https://goreportcard.com/badge/github.com/oauth2-proxy/mockoidc)](https://goreportcard.com/report/github.com/oauth2-proxy/mockoidc)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![Maintainability](https://api.codeclimate.com/v1/badges/99c0561090d1002dc7e3/maintainability)](https://codeclimate.com/github/oauth2-proxy/mockoidc/maintainability)
[![Test Coverage](https://api.codeclimate.com/v1/badges/99c0561090d1002dc7e3/test_coverage)](https://codeclimate.com/github/oauth2-proxy/mockoidc/test_coverage)

## Usage

Import the package
```
import "github.com/oauth2-proxy/mockoidc"
```

Start the MockOIDC Server. This will spin up a minimal OIDC server in its own
goroutine. It will listen on localhost on a random port.

Then pull its configuration to integrate it with your application. Begin
testing!

```
m, _ := mockoidc.Run()
defer m.Shutdown()

cfg := m.Config()
// type Config struct {
//   	ClientID     string
//   	ClientSecret string
//   	Issuer       string
//   
//   	AccessTTL  time.Duration
//   	RefreshTTL time.Duration
// }
```

### RunTLS

Alternatively, if you provide your own `tls.Config`, the server can run with
TLS:

```
tlsConfig = &tls.Config{
    // ...your TLS settings
}

m, _ := mockoidc.RunTLS(tlsConfig)
defer m.Shutdown()
```

### Endpoints

The following endpoints are implemented. They can either be pulled from the
OIDC discovery document (`m.Issuer() + "/.well-known/openid-configuration`)
or retrieved directly from the MockOIDC server.

```
m, _ := mockoidc.Run()
defer m.Shutdown()

m.Issuer()
m.DiscoveryEndpoint()
m.AuthorizationEndpoint()
m.TokenEndpoint()
m.UserinfoEndpoint()
m.JWKSEndpoint()
```

### Seeding Users and Codes

By default, calls to the `authorization_endpoint` will start a session as if
the `mockoidc.DefaultUser()` had logged in, and it will return a random code
for the `token_endpoint`. The User in the session started by this call to the
`authorization_endpoint` will be the one in the tokens returned by the
subsequent `token_endpoint` call.

These can be seeded with your own test Users & codes that will be returned:

```
m, _ := mockoidc.Run()
defer m.Shutdown()

user := &mockoidc.User{
    // User details...
}

// Add the User to the queue, this will be returned by the next login
m.QueueUser(user)

// Preset the code returned by the next login
m.QueueCode("12345")

// ...Request to m.AuthorizationEndpoint()
```

### Forcing Errors

Arbitrary errors can also be queued for handlers to return instead of their
default behavior:

```
m, err := mockoidc.Run()
defer m.Shutdown()

m.QueueError(&mockoidc.ServerError{
    Code: http.StatusInternalServerError,
    Error: mockoidc.InternalServerError,
    Description: "Some Custom Description",
})
```

### Manipulating Time

To accurately test token expiration scenarios, the MockOIDC server's view of
time is completely mutable.

You can override the server's view of `time.Now`

```
mockoidc.NowFunc = func() { //...custom logic }
```

As tests are running, you can fast-forward time to critical test points (e.g.
Access & Refresh Token expirations).

```
m, _ := mockoidc.Run()

m.FastForward(time.Duration(1) * time.Hour)
```

#### Synchronizing with `jwt-go` time

Even though we can fast-forward time, the underlying tokens processed by the
[jwt-go](https://github.com/dgrijalva/jwt-go) library still have timing logic.

We need to synchronize our timer with theirs:

```
m, _ := mockoidc.Run()
defer m.Shutdown()

// Overrides jwt.TimeFunc to m.Now
reset := m.Synchronize()

// reset is a mockoidc.ResetTime function that reverts jwt.TimeFunc to
// its original state
defer reset()
```

### Manual Configuration

Everything started up with `mockoidc.Run()` can be done manually giving the
opportunity to finely tune the settings:

```
// Create a fresh RSA Private Key for token signing
rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)

// Create an unstarted MockOIDC server
m, _ := mockoidc.NewServer(rsaKey)

// Create the net.Listener on the exact IP:Port you want
ln, _ := net.Listen("tcp", "127.0.0.1:8080")

tlsConfig = &tls.Config{
    // ...your TLS settings
}

// tlsConfig can be nil if you want HTTP
m.Start(ln, tlsConfig)
defer m.Shutdown()
```

Nearly all the MockOIDC struct is public. If you want to update any settings
to predefined values (e.g. `clientID`, `clientSecret`, `AccessTTL`,
`RefreshTTL`) you can before calling `m.Start`.

Additional internal components of the MockOIDC server are public if you need
to tamper with them as well:

```
type MockOIDC struct {
	// ...other stuff

	// Normally, these would be private. Expose them publicly for
	// power users.
	Server       *http.Server
	Keypair      *Keypair
	SessionStore *SessionStore
	UserQueue    *UserQueue
	ErrorQueue   *ErrorQueue
}
```

#### Adding Middleware

When configuring the MockOIDC server manually, you have the opportunity to add
custom middleware before starting the server (e.g. request logging, test
validators, etc).

```
m, _ := mockoidc.NewServer(nil)

middleware := func(next http.Handler) http.Handler {
    return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
        // custom middleware logic here...
        next.ServeHTTP(rw, req)
        // custom middleware logic here...
    })
}

m.AddMiddleware(middleware)
```

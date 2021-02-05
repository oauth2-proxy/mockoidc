# mockoidc

A Mock OpenID Connect Server for Authentication Unit and Integration Tests.

Created by @NickMeves and @egrif during the [Greenhouse Software](https://medium.com/in-the-weeds) Hack Day.

## Usage

Import the package
```
import "github.com/oauth2-proxy/mockoidc/v1"
```

Start the MockOIDC Server. This will spin up a minimal OIDC server in its own
goroutine. It will listen on localhost on a random port.

Then pulls its configuration to integrate it with your application.

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

reset := m.Synchronize()
// reset is a mockoidc.ResetTime function that reverts jwt.TimeFunc to
// its original state
defer reset()
```

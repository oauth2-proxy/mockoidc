package mockoidc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"

	"github.com/dgrijalva/jwt-go"
	"gopkg.in/square/go-jose.v2"
)

const DefaultPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAtI1Jf2zmfwLzpAjVarORtjKtmCHQtgNxqWDdVNVagCb092tL
rBRv0fTfHIJG+YpmmTrRN5yKax9bI3oSYNZJufAN3gu4TIrlLoFv6npC+k3rK+sb
iD2m0iz9duxe7uVSEHCJlcMas86Wa+VGBlAZQpnqh2TlaHXhyVbm+gHFGU0u26Pg
v5Esw2DEwRh0l7nK1ygg8dL/NNdtnaxTYhWAVPo4Vqcl2a9n+bs65maK02IgBLpa
LRUtjfjSIV17YBzlr6ekr7GwkDTD79d3Uc2GSSGzWqKlFtXmM9cFkfGGOYcaQLoE
LbkxaGfLmKI53HIxXUK28JjVCxITGl60u/Z5bQIDAQABAoIBADzUXS7RQdcI540c
bMrGNRFtgY7/1ZF9F445VFiAiT0j4uR5AcW4HPRfy8uPGNp6BpcZeeOCmh/9MHeD
aS23BJ/ggMuOp0kigpRoh4w4JNiv58ukKmJ8YvfssHigqltSZ5OiVrheQ2DQ+Vzg
ofb+hYQq1xlGpQPMs4ViAe+5KO6cwXYTL3j7PXAtE34Cl6JW36dd2U4G7EeEK8in
q+zCg6U0mtyudz+6YicOLXaNKmJaSUn8pWuWqUd14mpqgo54l46mMx9d/HmG45jp
MUam7qVYQ9ixtRp3vCUp5k4aSgigX0dn8pv3TGpSyq/t6g93DtMlXDY9rUjgQ3w5
Y8L+kAECgYEAz0sCr++a+rXHzLDdRpsI5nzYqpwB8GOJKTADrkil/F1PfQ3SAqGt
b4ioQNO054WQYHzZFryh4joTiOkmlgjM0k8eRJ4442ayJe6vm/apxWGkAiS0szoo
yUpH4OqVwUaDjA7yF3PBuMc1Ub65EQU9mcsEBVdlNO/hfF/1C2LupPECgYEA3vnC
JYp1MYy7zUSov70UTP/P01J5kIFYzY4VHRI4C0xZG4w/wjgsnYbGT1n9r14W/i7E
hEV1R0SxmbnrbfSt31niZfCfzl+jq7v/q0+6gm51y1sm68jdFSgwxcRKbD41jP3B
UNrfQhJdpB2FbSNAHQSng0XLVFfhDGFnzn277D0CgYAZ5glD6e+2+xcnX8GFnMET
6u03A57KZeUxHCqZj8INMatIuH1QjtqYYL6Euu6TLoDHTVHiIVcoaJEgPeDwRdEx
RWlGsW3yG1aOnq+aEMtNOdG/4s4gxldqLrmkRCrJpwGwcf2VKIU/jMQAno+IrNrx
aAfskuq2HnJRk7uN3KJsQQKBgQC0YCcGZ3NWmhpye1Bni3WYtHhS4y0kEP7dikra
MZrUyPZsqpAJdZfh9t0F5C6sZtkC1qJyvh2ZgaCKUzR4xq7BN91Fydn9ALFOg87X
rq+aQ/FWiG573wm5y8FoutnZppl7bOutlOF2eZT25krBdvqufs1kDFnn6Q9NDJ8F
FAGpoQKBgDMXVHVXNCJWO13/rwakBe4a9W/lbKuVX27wgCBcu3i/lGYjggm8GPka
Wk14b+reOmP3tZyZxDyX2zFyjkJpu2SWd5TlAL59vP3dzx+uyj6boWCCZHxzepli
5eHXOeVW+S+gwlCAF0U0n/XJ7Qhv0/SQnxSqT+D6V1+KbbeXnO7w
-----END RSA PRIVATE KEY-----`

type Keypair struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	Kid        string
}

func NewKeypair(key *rsa.PrivateKey) (*Keypair, error) {
	if key == nil {
		return DefaultKeypair()
	}

	return &Keypair{
		PrivateKey: key,
		PublicKey:  &key.PublicKey,
	}, nil
}

func RandomKeypair(size int) (*Keypair, error) {
	key, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		return nil, err
	}

	return &Keypair{
		PrivateKey: key,
		PublicKey:  &key.PublicKey,
	}, nil
}

func DefaultKeypair() (*Keypair, error) {
	block, _ := pem.Decode([]byte(DefaultPrivateKey))
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return &Keypair{
		PrivateKey: key,
		PublicKey:  &key.PublicKey,
	}, nil
}

func (k *Keypair) KeyID() (string, error) {
	if k.Kid != "" {
		return k.Kid, nil
	}

	publicKeyDERBytes, err := x509.MarshalPKIXPublicKey(k.PublicKey)
	if err != nil {
		return "", err
	}

	hasher := crypto.SHA256.New()
	if _, err := hasher.Write(publicKeyDERBytes); err != nil {
		return "", err
	}
	publicKeyDERHash := hasher.Sum(nil)

	k.Kid = base64.RawURLEncoding.EncodeToString(publicKeyDERHash)

	return k.Kid, nil
}

func (k *Keypair) JWKS() ([]byte, error) {
	kid, err := k.KeyID()
	if err != nil {
		return nil, err
	}

	jwk := jose.JSONWebKey{
		Use:       "sig",
		Algorithm: string(jose.RS256),
		Key:       k.PublicKey,
		KeyID:     kid,
	}
	jwks := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{jwk},
	}

	return json.Marshal(jwks)
}

func (k *Keypair) SignJWT(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	kid, err := k.KeyID()
	if err != nil {
		return "", err
	}
	token.Header["kid"] = kid

	return token.SignedString(k.PrivateKey)
}

func (k *Keypair) VerifyJWT(token string) (*jwt.Token, error) {
	return jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		kid, err := k.KeyID()
		if err != nil {
			return nil, err
		}
		if tk, ok := token.Header["kid"]; ok && tk == kid {
			return k.PublicKey, nil
		}
		return nil, errors.New("token kid does not match or is not present")
	})
}

func randomNonce(length int) (string, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

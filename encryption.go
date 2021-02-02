package mockoidc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/dgrijalva/jwt-go"
	"gopkg.in/square/go-jose.v2"
)

type Keypair struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	Kid        string
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

func (k *Keypair) KeyID() (string, error) {
	if k.Kid != "" {
		return k.Kid, nil
	}

	publicKeyDERBytes, err := x509.MarshalPKIXPublicKey(*k.PublicKey)
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

func (k *Keypair) JWKS() (string, error) {
	kid, err := k.KeyID()
	if err != nil {
		return "", err
	}

	jwk := jose.JSONWebKey{
		Use:       "sig",
		Algorithm: string(jose.RS256),
		Key:       k.PrivateKey,
		KeyID:     kid,
	}
	jwks := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{jwk},
	}

	jsonJWKS, err := json.Marshal(jwks)
	return string(jsonJWKS), err
}

func (k *Keypair) SignJWT(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), claims)

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

func nonce(length int) (string, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

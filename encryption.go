package mockoidc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/golang-jwt/jwt"
	"gopkg.in/square/go-jose.v2"
)

const DefaultKey = `MIIEowIBAAKCAQEAtI1Jf2zmfwLzpAjVarORtjKtmCHQtgNxqWDdVNVa` +
	`gCb092tLrBRv0fTfHIJG-YpmmTrRN5yKax9bI3oSYNZJufAN3gu4TIrlLoFv6npC-k3rK-s` +
	`biD2m0iz9duxe7uVSEHCJlcMas86Wa-VGBlAZQpnqh2TlaHXhyVbm-gHFGU0u26Pgv5Esw2` +
	`DEwRh0l7nK1ygg8dL_NNdtnaxTYhWAVPo4Vqcl2a9n-bs65maK02IgBLpaLRUtjfjSIV17Y` +
	`Bzlr6ekr7GwkDTD79d3Uc2GSSGzWqKlFtXmM9cFkfGGOYcaQLoELbkxaGfLmKI53HIxXUK2` +
	`8JjVCxITGl60u_Z5bQIDAQABAoIBADzUXS7RQdcI540cbMrGNRFtgY7_1ZF9F445VFiAiT0` +
	`j4uR5AcW4HPRfy8uPGNp6BpcZeeOCmh_9MHeDaS23BJ_ggMuOp0kigpRoh4w4JNiv58ukKm` +
	`J8YvfssHigqltSZ5OiVrheQ2DQ-Vzgofb-hYQq1xlGpQPMs4ViAe-5KO6cwXYTL3j7PXAtE` +
	`34Cl6JW36dd2U4G7EeEK8inq-zCg6U0mtyudz-6YicOLXaNKmJaSUn8pWuWqUd14mpqgo54` +
	`l46mMx9d_HmG45jpMUam7qVYQ9ixtRp3vCUp5k4aSgigX0dn8pv3TGpSyq_t6g93DtMlXDY` +
	`9rUjgQ3w5Y8L-kAECgYEAz0sCr--a-rXHzLDdRpsI5nzYqpwB8GOJKTADrkil_F1PfQ3SAq` +
	`Gtb4ioQNO054WQYHzZFryh4joTiOkmlgjM0k8eRJ4442ayJe6vm_apxWGkAiS0szooyUpH4` +
	`OqVwUaDjA7yF3PBuMc1Ub65EQU9mcsEBVdlNO_hfF_1C2LupPECgYEA3vnCJYp1MYy7zUSo` +
	`v70UTP_P01J5kIFYzY4VHRI4C0xZG4w_wjgsnYbGT1n9r14W_i7EhEV1R0SxmbnrbfSt31n` +
	`iZfCfzl-jq7v_q0-6gm51y1sm68jdFSgwxcRKbD41jP3BUNrfQhJdpB2FbSNAHQSng0XLVF` +
	`fhDGFnzn277D0CgYAZ5glD6e-2-xcnX8GFnMET6u03A57KZeUxHCqZj8INMatIuH1QjtqYY` +
	`L6Euu6TLoDHTVHiIVcoaJEgPeDwRdExRWlGsW3yG1aOnq-aEMtNOdG_4s4gxldqLrmkRCrJ` +
	`pwGwcf2VKIU_jMQAno-IrNrxaAfskuq2HnJRk7uN3KJsQQKBgQC0YCcGZ3NWmhpye1Bni3W` +
	`YtHhS4y0kEP7dikraMZrUyPZsqpAJdZfh9t0F5C6sZtkC1qJyvh2ZgaCKUzR4xq7BN91Fyd` +
	`n9ALFOg87Xrq-aQ_FWiG573wm5y8FoutnZppl7bOutlOF2eZT25krBdvqufs1kDFnn6Q9ND` +
	`J8FFAGpoQKBgDMXVHVXNCJWO13_rwakBe4a9W_lbKuVX27wgCBcu3i_lGYjggm8GPkaWk14` +
	`b-reOmP3tZyZxDyX2zFyjkJpu2SWd5TlAL59vP3dzx-uyj6boWCCZHxzepli5eHXOeVW-S-` +
	`gwlCAF0U0n_XJ7Qhv0_SQnxSqT-D6V1-KbbeXnO7w`

// Keypair is an RSA Keypair & JWT KeyID used for OIDC Token signing
type Keypair struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	Kid        string
}

// NewKeypair makes a Keypair off the provided rsa.PrivateKey or returns
// the package default if nil was passed
func NewKeypair(key *rsa.PrivateKey) (*Keypair, error) {
	if key == nil {
		return DefaultKeypair()
	}

	return &Keypair{
		PrivateKey: key,
		PublicKey:  &key.PublicKey,
	}, nil
}

// RandomKeypair creates a random rsa.PrivateKey and generates a key pair.
// This can be compute intensive, and should be avoided if called many
// times in a test suite.
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

// Returns the default Keypair built from DefaultKey
func DefaultKeypair() (*Keypair, error) {
	keyBytes, err := base64.RawURLEncoding.DecodeString(DefaultKey)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBytes)
	if err != nil {
		return nil, err
	}

	return &Keypair{
		PrivateKey: key,
		PublicKey:  &key.PublicKey,
	}, nil
}

// If not manually set, computes the JWT headers' `kid`
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

// JWKS is the JSON JWKS representation of the rsa.PublicKey
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

// SignJWT signs jwt.Claims with the Keypair and returns a token string
func (k *Keypair) SignJWT(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	kid, err := k.KeyID()
	if err != nil {
		return "", err
	}
	token.Header["kid"] = kid

	return token.SignedString(k.PrivateKey)
}

// VerifyJWT verifies the signature of a token was signed with this Keypair
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

package cot

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"

	"github.com/dgrijalva/jwt-go"
)

// JWK constants
const (
	JwkUseSig = "sig"
)

// JSONWebKey a JSON web key
type JSONWebKey struct {
	Alg    string   `json:"alg,omitempty"`
	Kty    string   `json:"kty,omitempty"`
	Use    string   `json:"use,omitempty"`
	X5c    []string `json:"x5c,omitempty"`
	N      string   `json:"n,omitempty"`
	E      string   `json:"e,omitempty"`
	Kid    string   `json:"kid,omitempty"`
	X5t    string   `json:"x5t,omitempty"`
	X5t256 string   `json:"x5t#S256,omitempty"`
	Sub    string   `json:"sub,omitempty"`
	Aud    string   `json:"aud,omitempty"`
}

// PublicKey returns the public key
func (c *JSONWebKey) PublicKey() (interface{}, error) {
	asn1Bytes, err := base64.StdEncoding.DecodeString(c.X5c[0])
	if err != nil {
		return nil, err
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}
	publicKeyPEM := pem.EncodeToMemory(block)

	switch c.Kty {
	case "RSA":
		return jwt.ParseRSAPublicKeyFromPEM(publicKeyPEM)
	case "EC":
		return jwt.ParseECPublicKeyFromPEM(publicKeyPEM)
	}

	return nil, fmt.Errorf("unsupported jwt algorithm %q", c.Kty)
}

// JSONWebKeySet a JSON web key set
type JSONWebKeySet struct {
	Keys []*JSONWebKey `json:"keys"`
}

// GetKey gets a specific key from the JWKS
func (c *JSONWebKeySet) GetKey(kid string) *JSONWebKey {
	for _, key := range c.Keys {
		if key.Kid == kid {
			return key
		}
	}
	return nil
}

// NewRS256JSONWebKey creates a new RS256 JSON web key
func NewRS256JSONWebKey(publicKey *rsa.PublicKey, kid, use, subject string) (*JSONWebKey, error) {
	asn1Bytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	x5t := sha1.Sum(asn1Bytes)
	x5t256 := sha256.Sum256(asn1Bytes)

	jwk := &JSONWebKey{
		Alg:    "RS256",
		Kty:    "RSA",
		Use:    use,
		X5c:    []string{base64.StdEncoding.EncodeToString(asn1Bytes)},
		N:      EncodeToString(publicKey.N.Bytes()),
		E:      EncodeUint64ToString(uint64(publicKey.E)),
		Kid:    kid,
		X5t:    EncodeToString(x5t[:]),
		X5t256: EncodeToString(x5t256[:]),
		Sub:    subject,
	}

	return jwk, nil
}

// EncodeToString encodes to string
func EncodeToString(src []byte) string {
	return base64.RawURLEncoding.EncodeToString(src)
}

// EncodeUint64ToString .
func EncodeUint64ToString(v uint64) string {
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, v)

	i := 0
	for ; i < len(data); i++ {
		if data[i] != 0x0 {
			break
		}
	}

	return EncodeToString(data[i:])
}

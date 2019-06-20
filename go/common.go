package cot

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

// keys
const (
	DefaultJwtTTL          = 60   // 1 minute
	MaxJwtTTL              = 1800 // 30 minutes, maximum time a Jwt can live. Not configurable
	DefaultBitSize         = 2048
	DefaultRequestTokenTTL = 1800
	TrusteeKeyPairSubject  = "trust_trustee_key"
	GrantorKeyPairSubject  = "trust_grantor_key"
	LogLevelDebug          = "debug"
	LogLevelError          = "error"
	LogLevelInfo           = "info"
	LogLevelWarn           = "warn"
	JwtIssuerClaim         = "iss"
	JwtExpiresAtClaim      = "exp"
	JwtKeyIDHeader         = "kid"
)

// vars
var (
	bearerRx           = regexp.MustCompile(`(?i)^(Bearer|JWT)\s+(.+)$`)
	ErrNoClientStore   = errors.New("no client store configured")
	ErrNoClientKeyPair = errors.New("no client key pair found in the store")
	ErrNotFound        = errors.New("not found")
)

// GenerateRSAKeyPair generates a key pair
func GenerateRSAKeyPair(keySize ...int) ([]byte, []byte, error) {
	bitSize := DefaultBitSize
	if len(keySize) > 0 && keySize[0] > 0 {
		bitSize = keySize[0]
	}
	if bitSize%1024 != 0 || bitSize == 0 {
		return nil, nil, fmt.Errorf("key size must be a multiple of 1024")
	}

	// generate a new key-pair
	reader := rand.Reader
	key, err := rsa.GenerateKey(reader, bitSize)
	if err != nil {
		return nil, nil, err
	}

	// encode public key
	asn1Bytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}

	privateKeyBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	privateKey := pem.EncodeToMemory(privateKeyBlock)
	publicKey := pem.EncodeToMemory(publicKeyBlock)

	// return results
	return privateKey, publicKey, nil
}

// SignRS256WithClaims signs claims with RS256
func SignRS256WithClaims(privateKeyPEM []byte, claims jwt.MapClaims, header map[string]interface{}) (string, error) {
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		return "", err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	if header != nil {
		for name, value := range header {
			token.Header[name] = value
		}
	}

	return token.SignedString(privateKey)
}

// ParseRS256 parses an RS256 tokenString
func ParseRS256(publicKeyPEM []byte, tokenString string) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return jwt.ParseRSAPublicKeyFromPEM(publicKeyPEM)
	})
}

// GetJwtFromRequest gets a jwt from the request
// accepts Authroization headers for Bearer and JWT
// also accepts Cookie with JWT
func GetJwtFromRequest(r *http.Request, cookieName string) (string, error) {
	match := bearerRx.FindAllStringSubmatch(r.Header.Get("Authorization"), -1)
	if len(match) > 0 {
		return strings.TrimSpace(match[0][2]), nil
	}

	if cookieName != "" {
		cookie, err := r.Cookie(cookieName)
		if err == nil {
			return strings.TrimSpace(cookie.Value), nil
		}
	}

	return "", fmt.Errorf("failed to extract token from request")
}

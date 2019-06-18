package cot

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/bhoriuchi/cot/go/store"
	"github.com/bhoriuchi/cot/go/types"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
)

// keys
const (
	DefaultBitSize         = 2048
	DefaultRequestTokenTTL = 1800
	ClientKeyPairSubject   = "trust_client_key"
	ServerKeyPairSubject   = "trust_server_key"
	LogLevelDebug          = "debug"
	LogLevelError          = "error"
	LogLevelInfo           = "info"
	LogLevelWarn           = "warn"
)

var (
	bearerRx = regexp.MustCompile(`(?i)^(Bearer|JWT)\s+(.+)$`)
)

// creates a keypair if it does not exist and returns it once it does
func ensureKeyPair(
	store store.Store,
	log func(level, message string, err error),
	keySubject string,
	keySize int,
	rotate bool,
) (*types.KeyPair, error) {
	// get the key pair for the subject
	pairs, err := store.GetKeyPairs([]string{keySubject})
	if err != nil {
		return nil, err
	}

	keyID := uuid.New().String()
	if len(pairs) > 0 {
		if !rotate {
			return pairs[0], nil
		}
		keyID = pairs[0].KeyID
	}

	// otherwise create and store a new keypair
	privateKey, publicKey, err := GenerateRSAKeyPair(keySize)
	if err != nil {
		log(LogLevelError, "Failed to generate trust key pair", err)
		return nil, err
	}

	keyPair := &types.KeyPair{
		KeyID:      keyID,
		Subject:    keySubject,
		PrivateKey: string(privateKey),
		PublicKey:  string(publicKey),
	}

	if err := store.PutKeyPair(keyPair); err != nil {
		log(LogLevelError, "Failed to put trust client key pair", err)
		return nil, err
	}

	return keyPair, nil
}

// create the jwks
func generateJWKS(
	store store.Store,
	log func(level, message string, err error),
	additionalJWKS func() []*JSONWebKey,
) (*JSONWebKeySet, error) {
	pairs, err := store.GetKeyPairs([]string{})
	if err != nil {
		log(LogLevelError, "Failed to get keypairs from the store", err)
		return nil, err
	}

	keys := []*JSONWebKey{}
	if additionalJWKS != nil {
		keys = additionalJWKS()
	}

	for _, pair := range pairs {
		publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(pair.PublicKey))
		if err != nil {
			log(LogLevelError, "Failed to parse public key from keypair", err)
			return nil, err
		}

		jwk, err := NewRS256JSONWebKey(publicKey, pair.KeyID, JwkUseSig, pair.Subject)
		if err != nil {
			log(LogLevelError, "Failed create a new JWK", err)
			return nil, err
		}

		keys = append(keys, jwk)
	}

	return &JSONWebKeySet{Keys: keys}, nil
}

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

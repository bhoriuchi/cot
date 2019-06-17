package cot

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// DefaultBitSize default
const DefaultBitSize = 2048

// GenerateRSAKeyPair generates a key pair
func GenerateRSAKeyPair(keySize ...int) ([]byte, []byte, error) {
	bitSize := DefaultBitSize
	if len(keySize) > 0 {
		bitSize = keySize[0]
	}
	if bitSize%1024 != 0 {
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

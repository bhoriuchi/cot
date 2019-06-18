package types

import (
	"errors"
	"net/url"
	"time"
)

// Errors
var (
	ErrInvalidRegistrationToken = errors.New("Invalid registration token")
	ErrExpiredRegistrationToken = errors.New("Registration token is expired")
	ErrInvalidJwksURL           = errors.New("Invalid JWKS URL")
	ErrInvalidKeyID             = errors.New("Invalid key ID")
	ErrInvalidPublicKey         = errors.New("Invalid public key")
	ErrInvalidPrivateKey        = errors.New("Invalid private key")
)

// RegistrationToken a registration token
type RegistrationToken struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
}

// Validate the registration token
func (c *RegistrationToken) Validate() error {
	if c.Token == "" {
		return ErrInvalidRegistrationToken
	} else if time.Now().Unix() >= c.ExpiresAt {
		return ErrExpiredRegistrationToken
	}
	return nil
}

// RegistrationRequest a registration request
type RegistrationRequest struct {
	Token string `json:"token"`
	URL   string `json:"url"`
	KeyID string `json:"key_id"`
}

// Validate validates a registration request
func (c *RegistrationRequest) Validate() error {
	if c.Token == "" {
		return ErrInvalidRegistrationToken
	} else if _, err := url.Parse(c.URL); err != nil || c.URL == "" {
		return ErrInvalidJwksURL
	} else if c.KeyID == "" {
		return ErrInvalidKeyID
	}
	return nil
}

// Trust a trust record
type Trust struct {
	KeyID    string `json:"key_id" yaml:"key_id"`
	URL      string `json:"url" yaml:"url"`
	Disabled bool   `json:"disabled" yaml:"disabled"`
}

// Validate validates the trust
func (c *Trust) Validate() error {
	if c.KeyID == "" {
		return ErrInvalidKeyID
	} else if _, err := url.Parse(c.URL); err != nil || c.URL == "" {
		return ErrInvalidJwksURL
	}
	return nil
}

// KeyPair a file containing the trust information
type KeyPair struct {
	KeyID      string `json:"id" yaml:"id"`
	PrivateKey string `json:"private_key" yaml:"private_key"`
	PublicKey  string `json:"public_key" yaml:"public_key"`
}

// Validate validates the trust
func (c *KeyPair) Validate() error {
	if c.KeyID == "" {
		return ErrInvalidKeyID
	} else if c.PrivateKey == "" {
		return ErrInvalidPrivateKey
	} else if c.PublicKey == "" {
		return ErrInvalidPublicKey
	}
	return nil
}

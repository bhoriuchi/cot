package types

import (
	"errors"
	"time"
)

// Errors
var (
	ErrInvalidRegistrationToken = errors.New("Invalid registration token")
	ErrExpiredRegistrationToken = errors.New("Registration token is expired")
	ErrInvalidAddress           = errors.New("Invalid address")
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
	Token   string `json:"token" yaml:"token"`
	KeyID   string `json:"key_id" yaml:"key_id"`
	Address string `json:"address" yaml:"address"`
}

// Validate validates a registration request
func (c *RegistrationRequest) Validate() error {
	if c.Token == "" {
		return ErrInvalidRegistrationToken
	} else if c.KeyID == "" {
		return ErrInvalidKeyID
	}
	return nil
}

// Trust a trust record
type Trust struct {
	KeyID    string `json:"key_id" yaml:"key_id"`
	Address  string `json:"address" yaml:"address"`
	Disabled bool   `json:"disabled" yaml:"disabled"`
}

// Validate validates the trust
func (c *Trust) Validate() error {
	if c.KeyID == "" {
		return ErrInvalidKeyID
	} else if c.Address == "" {
		return ErrInvalidAddress
	}
	return nil
}

// KeyPair a file containing the trust information
type KeyPair struct {
	KeyID      string `json:"id" yaml:"id"`
	Subject    string `json:"subject" yaml:"subject"`
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

// DistributedStoreUpdate a store update
type DistributedStoreUpdate struct {
	Trusts             []*Trust
	RegistrationTokens []*RegistrationToken
}

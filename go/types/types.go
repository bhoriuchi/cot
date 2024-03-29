package types

import (
	"time"
)

// StoredData data stored in the store
type StoredData struct {
	ID        string
	Data      interface{}
	Encrypted bool
}

// TrustRequest a request for a trust to be granted
type TrustRequest struct {
	GrantToken  string `json:"grant_token"  yaml:"grant_token"`
	KeyID       string `json:"key_id"       yaml:"key_id"`
	TrusteeAddr string `json:"trustee_addr" yaml:"trustee_addr"`
	Issuer      string `json:"issuer"       yaml:"issuer"`
}

// Validate validates a trust request
func (c *TrustRequest) Validate() error {
	if c.GrantToken == "" {
		return ErrInvalidGrantToken
	} else if c.KeyID == "" {
		return ErrInvalidKeyID
	} else if c.TrusteeAddr == "" {
		return ErrInvalidAddress
	} else if c.Issuer == "" {
		return ErrInvalidIssuer
	}
	return nil
}

// TrustGrantToken a trust grant token
type TrustGrantToken struct {
	ID         string `json:"id"          yaml:"id"`
	GrantToken string `json:"grant_token" yaml:"grant_token"`
	ExpiresAt  int64  `json:"expires_at"  yaml:"expires_at"`
	Issuer     string `json:"issuer"      yaml:"issuer"`
}

// Validate the registration token
func (c *TrustGrantToken) Validate() error {
	if c.GrantToken == "" {
		return ErrInvalidGrantToken
	} else if time.Now().Unix() >= c.ExpiresAt {
		return ErrExpiredRegistrationToken
	}
	return nil
}

// Trust a trust record
type Trust struct {
	ID          string `json:"id"           yaml:"id"`
	KeyID       string `json:"key_id"       yaml:"key_id"`
	TrusteeAddr string `json:"trustee_addr" yaml:"trustee_addr"`
	Disabled    bool   `json:"disabled"     yaml:"disabled"`
	Issuer      string `json:"issuer"       yaml:"issuer"`
}

// Validate validates the trust
func (c *Trust) Validate() error {
	if c.KeyID == "" {
		return ErrInvalidKeyID
	} else if c.TrusteeAddr == "" {
		return ErrInvalidAddress
	}
	return nil
}

// KeyPair a file containing the trust information
type KeyPair struct {
	ID         string `json:"id"          yaml:"id"`
	KeyID      string `json:"key_id"      yaml:"key_id"`
	Issuer     string `json:"issuer"      yaml:"issuer"`
	PrivateKey string `json:"private_key" yaml:"private_key"`
	PublicKey  string `json:"public_key"  yaml:"public_key"`
}

// Validate validates the trust
func (c *KeyPair) Validate() error {
	if c.KeyID == "" {
		return ErrInvalidKeyID
	} else if c.PrivateKey == "" {
		return ErrInvalidPrivateKey
	} else if c.PublicKey == "" {
		return ErrInvalidPublicKey
	} else if c.Issuer == "" {
		return ErrInvalidIssuer
	}
	return nil
}

// Notification an event message
type Notification struct {
	ID        string
	Topic     string
	Event     string
	Data      string
	Source    string
	ExpiresAt int64
}

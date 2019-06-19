package types

import "errors"

// Errors
var (
	ErrInvalidJwtToken          = errors.New("invalid JWT token")
	ErrKeyIDNotFound            = errors.New("key ID not found")
	ErrInvalidGrantToken        = errors.New("invalid grant token")
	ErrInvalidRegistrationToken = errors.New("Invalid registration token")
	ErrExpiredRegistrationToken = errors.New("Registration token is expired")
	ErrInvalidAddress           = errors.New("Invalid address")
	ErrInvalidKeyID             = errors.New("Invalid key ID")
	ErrInvalidPublicKey         = errors.New("Invalid public key")
	ErrInvalidPrivateKey        = errors.New("Invalid private key")
)

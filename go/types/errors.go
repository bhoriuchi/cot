package types

import "errors"

// Errors
var (
	ErrInvalidJwtToken          = errors.New("invalid JWT token")
	ErrKeyIDNotFound            = errors.New("key ID not found")
	ErrInvalidGrantToken        = errors.New("invalid grant token")
	ErrInvalidRegistrationToken = errors.New("invalid registration token")
	ErrExpiredRegistrationToken = errors.New("registration token is expired")
	ErrInvalidAddress           = errors.New("invalid address")
	ErrInvalidKeyID             = errors.New("invalid key ID")
	ErrInvalidPublicKey         = errors.New("invalid public key")
	ErrInvalidPrivateKey        = errors.New("invalid private key")
	ErrInvalidIssuer            = errors.New("invalid issuer")
	ErrUnknownIssuer            = errors.New("no corresponding key pair for issuer")
	ErrNoIssuerInClaim          = errors.New("no issuer was provided in the claim")
	ErrBadIssuer                = errors.New("the issuer provided in the claim does not match the trust")
	ErrNoKeyIDInHeader          = errors.New("no key ID (kid) found in token header")
)

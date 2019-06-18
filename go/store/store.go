package store

import (
	"github.com/bhoriuchi/cot/go/types"
)

// Type enum
type Type string

// Store types
var (
	StoreTypeShared      Type = "shared"      // shared means that all peers share access to the same store data (i.e. database)
	StoreTypeDistributed Type = "distributed" // distributed means that all peers have their own local copy of the store data (i.e. embedded db)
)

// Store interface to a store
type Store interface {
	Init() error
	Type() Type
	WithLogFunc(logFunc func(level, message string, err error)) Store

	// registration tokens
	PutRegistrationToken(token *types.RegistrationToken) error
	DeleteRegistrationTokens(ids []string) error
	GetRegistrationTokens(ids []string) ([]*types.RegistrationToken, error)

	// keypairs
	PutKeyPair(pair *types.KeyPair) error
	DeleteKeyPairs(id []string) error
	GetKeyPairs(ids []string) ([]*types.KeyPair, error)

	// trusts
	PutTrust(trust *types.Trust) error
	DeleteTrusts(ids []string) error
	GetTrusts(ids []string) ([]*types.Trust, error)
}

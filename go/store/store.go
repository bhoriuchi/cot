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

	// trust grant tokens
	PutTrustGrantToken(token *types.StoredData) (string, error)
	DeleteTrustGrantTokens(ids []string) error
	GetTrustGrantTokens(ids []string) ([]*types.StoredData, error)

	// keypairs
	PutKeyPair(pair *types.StoredData) (string, error)
	DeleteKeyPairs(id []string) error
	GetKeyPairs(ids []string) ([]*types.StoredData, error)

	// trusts
	PutTrust(trust *types.StoredData) (string, error)
	DeleteTrusts(ids []string) error
	GetTrusts(ids []string) ([]*types.StoredData, error)
}

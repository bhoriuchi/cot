package cot

import (
	"github.com/bhoriuchi/cot/go/store"
	"github.com/bhoriuchi/cot/go/types"
	"github.com/google/uuid"
)

// Logger a logging function
type Logger func(level, message string, err error)

// Node a circle of trust node
type Node struct {
	keySize              int
	requestTimeout       int
	registrationTokenTTL int
	initialized          bool
	insecure             bool
	cliMode              bool
	rpcAddr              string
	jwtCookieName        string
	encryptionKey        string
	log                  Logger
	store                store.Store
	additionalJwkFunc    func() []*JSONWebKey
	trusteeKeyPair       *types.KeyPair
	grantorKeyPair       *types.KeyPair
	trustJWKS            *JSONWebKeySet
}

// NodeOptions options for a node
type NodeOptions struct {
	KeySize              int
	RequestTimeout       int
	RegistrationTokenTTL int
	Insecure             bool
	CLIMode              bool
	RPCAddr              string
	JWTCookieName        string
	EncryptionKey        string
	LogFunc              Logger
	Store                store.Store
	AdditionalJWKFunc    func() []*JSONWebKey
}

// NewNode creates a new node
func NewNode(opts *NodeOptions) *Node {
	o := &NodeOptions{}
	if opts != nil {
		o = opts
	}

	if o.LogFunc == nil {
		o.LogFunc = func(level, message string, err error) {}
	}

	if o.RegistrationTokenTTL == 0 {
		o.RegistrationTokenTTL = DefaultRequestTokenTTL
	}

	if o.AdditionalJWKFunc == nil {
		o.AdditionalJWKFunc = func() []*JSONWebKey {
			return []*JSONWebKey{}
		}
	}

	return &Node{
		keySize:              o.KeySize,
		requestTimeout:       o.RequestTimeout,
		registrationTokenTTL: o.RegistrationTokenTTL,
		initialized:          false,
		insecure:             o.Insecure,
		cliMode:              o.CLIMode,
		rpcAddr:              o.RPCAddr,
		jwtCookieName:        o.JWTCookieName,
		encryptionKey:        o.EncryptionKey,
		log:                  o.LogFunc,
		store:                o.Store,
		additionalJwkFunc:    o.AdditionalJWKFunc,
		trustJWKS:            &JSONWebKeySet{Keys: []*JSONWebKey{}},
	}
}

// Serve initializes the node and starts serving
func (c *Node) Serve() error {
	var err error
	if c.initialized {
		return nil
	}

	c.log(LogLevelDebug, "Initializing the trust node", nil)

	// validate the client options
	if c.rpcAddr == "" && !c.cliMode {
		c.log(LogLevelError, "Invalid trust node RPC address", types.ErrInvalidAddress)
		return types.ErrInvalidAddress
	} else if c.store == nil {
		c.log(LogLevelError, "No store provided to trust node", ErrNoClientStore)
		return ErrNoClientStore
	}

	// check if shared store and no encryption
	// this is potentially dangerous since a shared store is likely a database
	// that will be storing the private keys in plain text
	// log a warning
	if c.store.Type() == store.StoreTypeShared && c.encryptionKey == "" {
		c.log(LogLevelWarn, "Using a shared store with no encryption leave private keys potentially insecure", nil)
	}

	// initialize the store
	c.log(LogLevelDebug, "Initializing the nodes trust store", nil)
	if err := c.store.WithLogFunc(c.log).Init(); err != nil {
		c.log(LogLevelError, "Failed to initialize the nodes trust store", err)
		return err
	}

	// set up trustee and grantor keypairs
	if c.trusteeKeyPair, err = c.ensureKeyPair(TrusteeKeyPairSubject, false); err != nil {
		c.log(LogLevelError, "Failed to ensure trust trustee key pair", err)
		return err
	}

	if c.grantorKeyPair, err = c.ensureKeyPair(GrantorKeyPairSubject, false); err != nil {
		c.log(LogLevelError, "Failed to ensure trust grantor key pair", err)
		return err
	}

	// start the rpc server
	if !c.cliMode {
		rpcServer := &NodeRPCServer{node: c}
		if err := rpcServer.serve(); err != nil {
			c.log(LogLevelError, "Failed to start trust node RPC", err)
			return err
		}
	}

	// refresh all trusts
	if err := c.refreshAllTrusts(); err != nil {
		c.log(LogLevelError, "Failed to refresh all trusts", err)
	}

	c.log(LogLevelDebug, "SUCCESS! Initialized the trust node", nil)
	c.initialized = true
	return nil
}

// creates a keypair if it does not exist and returns it once it does
func (c *Node) ensureKeyPair(keySubject string, rotate bool) (*types.KeyPair, error) {
	// get the key pair for the subject
	keyPair, err := c.findKeyPair(keySubject)
	if err != nil && err != ErrNotFound {
		return nil, err
	}

	// get the keyID
	keyPairID := ""
	keyID := uuid.New().String()
	if keyPair != nil {
		if !rotate {
			return keyPair, nil
		}
		keyPairID = keyPair.ID
		keyID = keyPair.KeyID
	}

	// otherwise create and store a new keypair
	privateKey, publicKey, err := GenerateRSAKeyPair(c.keySize)
	if err != nil {
		c.log(LogLevelError, "Failed to generate trust key pair", err)
		return nil, err
	}

	keyPair = &types.KeyPair{
		ID:         keyPairID,
		KeyID:      keyID,
		Subject:    keySubject,
		PrivateKey: string(privateKey),
		PublicKey:  string(publicKey),
	}

	if _, err := c.putKeyPair(keyPairID, keyPair); err != nil {
		return nil, err
	}

	return keyPair, nil
}

// ListTrusts lists all trusts
func (c *Node) ListTrusts() ([]*types.Trust, error) {
	return c.getTrusts([]string{})
}

// ListKeyPairs lists all trusts
func (c *Node) ListKeyPairs() ([]*types.KeyPair, error) {
	return c.getKeyPairs([]string{})
}

// ListTrustGrantTokens lists all trusts
func (c *Node) ListTrustGrantTokens() ([]*types.TrustGrantToken, error) {
	return c.getTrustGrantTokens([]string{})
}

// NotifyPeers let peers know of a trust update
func (c *Node) NotifyPeers() {

}

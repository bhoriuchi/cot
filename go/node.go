package cot

import (
	"github.com/bhoriuchi/cot/go/store"
	"github.com/bhoriuchi/cot/go/types"
	"github.com/dgrijalva/jwt-go"
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
	keyPairs             map[string]*types.KeyPair
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
		keyPairs:             map[string]*types.KeyPair{},
		trustJWKS:            &JSONWebKeySet{Keys: []*JSONWebKey{}},
	}
}

// Serve initializes the node and starts serving
func (c *Node) Serve() error {
	var err error
	if c.initialized {
		return nil
	}

	c.log(LogLevelDebug, "initializing the trust node", nil)

	// validate the client options
	if c.rpcAddr == "" && !c.cliMode {
		c.log(LogLevelError, "invalid trust node RPC address", types.ErrInvalidAddress)
		return types.ErrInvalidAddress
	} else if c.store == nil {
		c.log(LogLevelError, "no store provided to trust node", ErrNoClientStore)
		return ErrNoClientStore
	}

	// check if shared store and no encryption
	// this is potentially dangerous since a shared store is likely a database
	// that will be storing the private keys in plain text
	// log a warning
	if c.store.Type() == store.StoreTypeShared && c.encryptionKey == "" {
		c.log(LogLevelWarn, "using a shared store with no encryption leave private keys potentially insecure", nil)
	}

	// initialize the store
	c.log(LogLevelDebug, "initializing the nodes trust store", nil)
	if err := c.store.WithLogFunc(c.log).Init(); err != nil {
		c.log(LogLevelError, "failed to initialize the nodes trust store", err)
		return err
	}

	// get current key pairs
	keyPairs, err := c.getKeyPairs([]string{})
	if err != nil {
		return err
	}
	for _, keyPair := range keyPairs {
		c.keyPairs[keyPair.Issuer] = keyPair
	}

	// start the rpc server
	if !c.cliMode {
		rpcServer := &NodeRPCServer{node: c}
		if err := rpcServer.serve(); err != nil {
			c.log(LogLevelError, "failed to start trust node RPC", err)
			return err
		}
	}

	// refresh all trusts
	if err := c.refreshAllTrusts(); err != nil {
		c.log(LogLevelError, "failed to refresh all trusts", err)
	}

	c.log(LogLevelDebug, "SUCCESS! Initialized the trust node", nil)
	c.initialized = true
	return nil
}

// NewKeyPair creates a new key pair for the issuer
// if the issuer key pair exists it rotates the key pair
func (c *Node) NewKeyPair(issuer string, rotateIfExists bool) (*types.KeyPair, error) {
	return c.ensureKeyPair(issuer, rotateIfExists)
}

// creates a keypair if it does not exist and returns it once it does
func (c *Node) ensureKeyPair(issuer string, rotate bool) (*types.KeyPair, error) {
	// get the key pair for the subject
	keyPair, err := c.findKeyPair(issuer)
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
		c.log(LogLevelError, "failed to generate trust key pair", err)
		return nil, err
	}

	keyPair = &types.KeyPair{
		ID:         keyPairID,
		KeyID:      keyID,
		Issuer:     issuer,
		PrivateKey: string(privateKey),
		PublicKey:  string(publicKey),
	}

	if _, err := c.putKeyPair(keyPairID, keyPair); err != nil {
		return nil, err
	}

	return keyPair, nil
}

// gets the key pair from the tokens issuer
func (c *Node) validateTokenIssuer(token *jwt.Token) (*JSONWebKey, error) {
	kid, hasKeyID := token.Header[JwtKeyIDHeader]
	if !hasKeyID {
		return nil, types.ErrNoKeyIDInHeader
	}

	issuer, hasIssuer := token.Claims.(jwt.MapClaims)[JwtIssuerClaim]
	if !hasIssuer {
		return nil, types.ErrNoIssuerInClaim
	}

	jwk := c.trustJWKS.GetKey(kid.(string))
	if jwk == nil {
		return nil, types.ErrKeyIDNotFound
	}

	if jwk.Issuer != issuer.(string) {
		return nil, types.ErrBadIssuer
	}

	return jwk, nil
}

// RotateKeyPair rotates the trustee keypair
func (c *Node) RotateKeyPair(issuer string) error {
	keyPair, err := c.ensureKeyPair(issuer, true)
	if err != nil {
		return err
	}
	c.keyPairs[issuer] = keyPair
	return nil
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

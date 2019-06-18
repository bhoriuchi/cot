package cot

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/rpc"
	"time"

	"github.com/bhoriuchi/cot/go/store"
	"github.com/bhoriuchi/cot/go/types"
	"github.com/dgrijalva/jwt-go"
)

// constants
const (
	DefaultHTTPRequestTimeout = 30
	DefaultJwtTTL             = 60   // 1 minute
	MaxJwtTTL                 = 1800 // 30 minutes, maximum time a Jwt can live. Not configurable
)

// Errors
var (
	ErrNoClientStore   = errors.New("No client store configured")
	ErrNoClientKeyPair = errors.New("No client key pair found in the store")
)

// ClientRPC a client rpc
type ClientRPC struct {
	client *Client
}

// GetJWK get the jwk
func (c *ClientRPC) GetJWK(args *string, reply *JSONWebKey) error {
	c.client.log(LogLevelDebug, fmt.Sprintf("RPC request for trust client jwk with key ID %s", *args), nil)
	jwks, err := generateJWKS(c.client.store, c.client.log, c.client.additionalJWK)
	if err != nil {
		return err
	}
	jwk := jwks.GetKey(*args)
	*reply = *jwk
	return nil
}

func (c *ClientRPC) run() error {
	c.client.log(LogLevelDebug, fmt.Sprintf("Starting trust client RPC on %s", c.client.rpcAddr), nil)
	handler := rpc.NewServer()
	handler.Register(c)
	ln, err := net.Listen("tcp", c.client.rpcAddr)
	if err != nil {
		c.client.log(LogLevelError, "Failed to create listener", err)
		return err
	}
	go func() {
		for {
			cxn, err := ln.Accept()
			if err != nil {
				c.client.log(LogLevelError, "Failed to accept connection", err)
				return
			}
			go handler.ServeConn(cxn)
		}
	}()
	c.client.log(LogLevelDebug, fmt.Sprintf("SUCCESS! Started trust client RPC on %s", c.client.rpcAddr), nil)
	return nil
}

// NewClient creates a new client
func NewClient(opts *ClientOptions) *Client {
	o := &ClientOptions{}
	if opts != nil {
		o = opts
	}

	timeout := DefaultHTTPRequestTimeout
	if o.RequestTimeout > 0 {
		timeout = o.RequestTimeout
	}

	if o.LogFunc == nil {
		o.LogFunc = func(level, message string, err error) {}
	}

	return &Client{
		cliMode: o.CLIMode,
		rpcAddr: o.RPCAddr,
		store:   o.Store,
		keySize: o.KeySize,
		httpClient: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: o.Insecure},
			},
		},
		log:           o.LogFunc,
		additionalJWK: o.AdditionalJWKFunc,
	}
}

// ClientOptions options for the client
type ClientOptions struct {
	CLIMode           bool
	RPCAddr           string
	Store             store.Store
	KeySize           int
	RequestTimeout    int
	Insecure          bool
	LogFunc           func(level, message string, err error)
	AdditionalJWKFunc func() []*JSONWebKey
}

// Client a cot client
type Client struct {
	cliMode       bool
	rpcAddr       string
	clientRPC     *ClientRPC
	initialized   bool
	keySize       int
	httpClient    *http.Client
	store         store.Store
	clientKeyPair *types.KeyPair
	log           func(level, message string, err error)
	additionalJWK func() []*JSONWebKey
}

// Init initializes a client
func (c *Client) Init() error {
	if c.initialized {
		return nil
	}

	c.log(LogLevelDebug, "Initializing the trust client", nil)

	// validate the client options
	if c.rpcAddr == "" {
		c.log(LogLevelError, "Invalid trust client RPC address", types.ErrInvalidAddress)
		return types.ErrInvalidAddress
	} else if c.store == nil {
		c.log(LogLevelError, "No store provided", ErrNoClientStore)
		return ErrNoClientStore
	}

	c.log(LogLevelDebug, "Initializing the trust client store", nil)
	if err := c.store.WithLogFunc(c.log).Init(); err != nil {
		c.log(LogLevelError, "Failed to initialize the trust client store", err)
		return err
	}

	// ensure a client key pair
	keyPair, err := ensureKeyPair(c.store, c.log, ClientKeyPairSubject, c.keySize, false)
	if err != nil {
		c.log(LogLevelError, "Failed to ensure trust client key pair", err)
		return err
	}

	// start the rpc server
	if !c.cliMode {
		c.clientRPC = &ClientRPC{client: c}
		if err := c.clientRPC.run(); err != nil {
			c.log(LogLevelError, "Failed to start trust client RPC server", err)
			return err
		}
	}

	c.log(LogLevelDebug, "SUCCESS! Initialized the trust client", nil)
	c.clientKeyPair = keyPair
	c.initialized = true
	return nil
}

// Register registers a client
func (c *Client) Register(uri, token string) error {
	if err := c.Init(); err != nil {
		return err
	}

	request := &types.RegistrationRequest{
		Token:   token,
		KeyID:   c.clientKeyPair.KeyID,
		Address: c.rpcAddr,
	}

	j, err := json.Marshal(request)
	if err != nil {
		c.log(LogLevelError, "Failed to marshal trust client register request JSON", err)
		return err
	}
	b := bytes.NewBuffer(j)

	resp, err := c.httpClient.Post(uri, "application/json", b)
	if err != nil {
		c.log(LogLevelError, "Failed to POST trust client register", err)
		return err
	}

	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("Registration failed with: %s", resp.Status)
		c.log(LogLevelError, "Registration request failed", err)
		return err
	}

	return nil
}

// Sign signs the claims with the client key
func (c *Client) Sign(claims jwt.MapClaims, ttl ...int) (string, error) {
	if err := c.Init(); err != nil {
		return "", err
	}

	c.log(LogLevelDebug, "Signing a trust client JWT", nil)
	expiresIn := MaxJwtTTL

	if len(ttl) > 0 {
		if ttl[0] > 1 && ttl[0] <= MaxJwtTTL {
			expiresIn = ttl[0]
		}
	}

	// add expiration
	claims["exp"] = time.Now().Unix() + int64(expiresIn)
	header := map[string]interface{}{
		"kid": c.clientKeyPair.KeyID,
	}

	return SignRS256WithClaims([]byte(c.clientKeyPair.PrivateKey), claims, header)
}

// RotateKeyPair rotates the keypair
func (c *Client) RotateKeyPair() error {
	_, err := ensureKeyPair(c.store, c.log, ClientKeyPairSubject, c.keySize, true)
	return err
}

// HandleGetJWKS serves the current JWKS
func (c *Client) HandleGetJWKS(w http.ResponseWriter, r *http.Request) {
	if err := c.Init(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// get the JWKS
	jwks, err := generateJWKS(c.store, c.log, c.additionalJWK)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// write the response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(jwks); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

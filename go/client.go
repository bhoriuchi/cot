package cot

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/bhoriuchi/cot/go/store"
	"github.com/bhoriuchi/cot/go/types"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
)

// constants
const (
	DefaultHTTPRequestTimeout = 30
	DefaultJwtTTL             = 60   // 1 minute
	MaxJwtTTL                 = 1800 // 30 minutes, maximum time a Jwt can live. Not configurable
	ClientKeyPairID           = "client_keypair_id"
)

// Errors
var (
	ErrInvalidClientJwksURL = errors.New("Invalid client JWKS URL")
	ErrNoClientStore        = errors.New("No client store configured")
	ErrNoClientKeyPair      = errors.New("No client key pair found in the store")
)

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
		jwksURL: o.JwksURL,
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
	JwksURL           string
	Store             store.Store
	KeySize           int
	RequestTimeout    int
	Insecure          bool
	LogFunc           func(level, message string, err error)
	AdditionalJWKFunc func() []*JSONWebKey
}

// Client a cot client
type Client struct {
	initialized   bool
	jwksURL       string
	keySize       int
	httpClient    *http.Client
	store         store.Store
	clientKeyPair *types.KeyPair
	log           func(level, message string, err error)
	additionalJWK func() []*JSONWebKey
}

// check if the client key pair has been
func (c *Client) getClientKeyPair() (*types.KeyPair, error) {
	keyPairs, err := c.store.GetKeyPairs([]string{ClientKeyPairID})
	if err != nil {
		c.log(LogLevelError, "Failed to get trust client key pair", err)
		return nil, err
	} else if len(keyPairs) == 1 {
		return keyPairs[0], nil
	}
	c.log(LogLevelError, "Failed to get trust client key pair", ErrNoClientKeyPair)
	return nil, ErrNoClientKeyPair
}

// Init initializes a client
func (c *Client) Init() error {
	if c.initialized {
		return nil
	}

	c.log(LogLevelDebug, "Initializing the trust client", nil)

	// validate the client options
	if _, err := url.Parse(c.jwksURL); err != nil || c.jwksURL == "" {
		c.log(LogLevelError, "Invalid JWKS url", ErrInvalidClientJwksURL)
		return ErrInvalidClientJwksURL
	} else if c.store == nil {
		c.log(LogLevelError, "No store provided", ErrNoClientStore)
		return ErrNoClientStore
	}

	c.log(LogLevelDebug, "Initializing the trust client store", nil)
	if err := c.store.WithLogFunc(c.log).Init(); err != nil {
		c.log(LogLevelError, "Failed to initialize the trust client store", err)
		return err
	}

	c.log(LogLevelDebug, "Retrieving the trust client key id", nil)
	clientKeyID, ok, err := c.store.GetTrustClientConfig(ClientKeyPairID)
	if err != nil {
		c.log(LogLevelError, "Failed to get trust client config", err)
		return err
	}
	if !ok {
		// if no id, create a new one and store it
		c.log(LogLevelDebug, "Generating a new trust client key id", nil)
		clientKeyID = uuid.New().String()
		if err := c.store.PutTrustClientConfig(ClientKeyPairID, clientKeyID); err != nil {
			c.log(LogLevelError, "Failed to put trust client config", err)
			return err
		}

		c.log(LogLevelDebug, "Generating a new trust client key pair", nil)
		clientKeyPair, err := c.newKeyPair(clientKeyID)
		if err != nil {
			c.log(LogLevelError, "Failed to generate a new trust client key pair", err)
			return err
		}
		c.clientKeyPair = clientKeyPair
	} else {
		// if id found, check that a key pair exists, if not create one
		c.log(LogLevelDebug, "Retrieving trust client key pair", nil)
		pairs, err := c.store.GetKeyPairs([]string{clientKeyID})
		if err != nil {
			c.log(LogLevelError, "Failed to get trust client key pair", err)
			return err
		}
		if len(pairs) == 1 {
			c.clientKeyPair = pairs[0]
		} else {
			c.log(LogLevelDebug, "No trust client key pair found, generating a new one", nil)
			clientKeyPair, err := c.newKeyPair(clientKeyID)
			if err != nil {
				c.log(LogLevelError, "Failed to generate a new trust client key pair", err)
				return err
			}
			c.clientKeyPair = clientKeyPair
		}
	}

	c.log(LogLevelDebug, "SUCCESS! Initialized the trust client", nil)
	c.initialized = true
	return nil
}

// generates a new keypair and stores it with the key id
func (c *Client) newKeyPair(keyID string) (*types.KeyPair, error) {
	// now generate a new keypair and store it
	privateKey, publicKey, err := GenerateRSAKeyPair(c.keySize)
	if err != nil {
		return nil, err
	}

	clientKeyPair := &types.KeyPair{
		KeyID:      keyID,
		PrivateKey: string(privateKey),
		PublicKey:  string(publicKey),
	}

	if err := c.store.PutKeyPair(clientKeyPair); err != nil {
		c.log(LogLevelError, "Failed to put trust client key pair", err)
		return nil, err
	}

	return clientKeyPair, nil
}

// Register registers a client
func (c *Client) Register(uri, token string) error {
	if err := c.Init(); err != nil {
		return err
	}

	request := &types.RegistrationRequest{
		Token: token,
		KeyID: c.clientKeyPair.KeyID,
		URL:   c.jwksURL,
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

// JSONWebKeySet returns the current combined JWKS
func (c *Client) JSONWebKeySet() (*JSONWebKeySet, error) {
	if err := c.Init(); err != nil {
		return nil, err
	}

	kid := c.clientKeyPair.KeyID
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(c.clientKeyPair.PublicKey))
	if err != nil {
		return nil, err
	}

	jwk, err := NewRS256JSONWebKey(publicKey, kid, JwkUseSig)
	if err != nil {
		return nil, err
	}

	keyMap := map[string]string{kid: kid}
	jwks := &JSONWebKeySet{Keys: []*JSONWebKey{jwk}}

	// add additional jwk
	if c.additionalJWK != nil {
		additionalJWK := c.additionalJWK()
		if additionalJWK != nil {
			for _, a := range additionalJWK {
				if _, ok := keyMap[a.Kid]; !ok {
					keyMap[a.Kid] = a.Kid
					jwks.Keys = append(jwks.Keys, a)
				}
			}
		}
	}

	return jwks, nil
}

// HandleGetJWKS serves the current JWKS
func (c *Client) HandleGetJWKS(w http.ResponseWriter, r *http.Request) {
	// get the JWKS
	jwks, err := c.JSONWebKeySet()
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

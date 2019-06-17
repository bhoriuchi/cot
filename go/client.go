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
		return nil, err
	} else if len(keyPairs) == 1 {
		return keyPairs[0], nil
	}
	return nil, ErrNoClientKeyPair
}

// Init initializes a client
func (c *Client) Init() error {
	if c.initialized {
		return nil
	}

	// validate the client options
	if _, err := url.Parse(c.jwksURL); err != nil || c.jwksURL == "" {
		return ErrInvalidClientJwksURL
	} else if c.store == nil {
		return ErrNoClientStore
	}

	if err := c.store.Init(); err != nil {
		return err
	}

	clientKeyID, ok, err := c.store.GetTrustClientConfig(ClientKeyPairID)
	if err != nil {
		return err
	}
	if !ok {
		// if no id, create a new one and store it
		clientKeyID = uuid.New().String()
		if err := c.store.PutTrustClientConfig(ClientKeyPairID, clientKeyID); err != nil {
			return err
		}

		clientKeyPair, err := c.newKeyPair(clientKeyID)
		if err != nil {
			return err
		}
		c.clientKeyPair = clientKeyPair
	} else {
		// if id found, check that a key pair exists, if not create one
		pairs, err := c.store.GetKeyPairs([]string{clientKeyID})
		if err != nil {
			return err
		}
		if len(pairs) == 1 {
			c.clientKeyPair = pairs[0]
		} else {
			clientKeyPair, err := c.newKeyPair(clientKeyID)
			if err != nil {
				return err
			}
			c.clientKeyPair = clientKeyPair
		}
	}

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
		return err
	}
	b := bytes.NewBuffer(j)

	resp, err := c.httpClient.Post(uri, "application/json", b)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("registration failed with: %s", resp.Status)
	}

	return nil
}

// Sign signs the claims with the client key
func (c *Client) Sign(claims jwt.MapClaims) (string, error) {
	if err := c.Init(); err != nil {
		return "", err
	}

	currentTime := time.Now().Unix()

	// enforce a min and max expiration
	expiresAt, ok := claims["exp"]
	if !ok || expiresAt.(int64) <= currentTime {
		expiresAt = currentTime + DefaultJwtTTL
	}
	if expiresAt.(int64) >= currentTime+MaxJwtTTL {
		expiresAt = currentTime + MaxJwtTTL
	}

	claims["kid"] = c.clientKeyPair.KeyID
	claims["exp"] = expiresAt

	return SignRS256WithClaims([]byte(c.clientKeyPair.PrivateKey), claims)
}

// HandleGetJWKS serves the current JWKS
func (c *Client) HandleGetJWKS(w http.ResponseWriter, r *http.Request) {
	if err := c.Init(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	kid := c.clientKeyPair.KeyID
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(c.clientKeyPair.PublicKey))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	jwk, err := NewRS256JSONWebKey(publicKey, kid, JwkUseSig)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	keyMap := map[string]string{kid: kid}
	jwks := &JSONWebKeySet{Keys: []*JSONWebKey{jwk}}

	// add additional jwk
	additionalJWK := c.additionalJWK()
	if additionalJWK != nil {
		for _, a := range additionalJWK {
			if _, ok := keyMap[a.Kid]; !ok {
				keyMap[a.Kid] = a.Kid
				jwks.Keys = append(jwks.Keys, a)
			}
		}
	}

	// write the response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(jwks); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

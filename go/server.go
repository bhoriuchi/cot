package cot

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/bhoriuchi/cot/go/store"
	"github.com/bhoriuchi/cot/go/types"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
)

// Server constants
const (
	DefaultRequestTokenTTL = 1800
	LogLevelDebug          = "debug"
	LogLevelError          = "error"
	LogLevelInfo           = "info"
	LogLevelWarn           = "warn"
)

// Server a resource server
type Server struct {
	peers                map[string]string
	initialized          bool
	registrationTokenTTL int
	store                store.Store
	log                  func(level, message string, err error)
	trustJWKS            *JSONWebKeySet
	httpClient           *http.Client
}

// ServerOptions options for server
type ServerOptions struct {
	Insecure             bool
	RequestTimeout       int
	RegistrationTokenTTL int
	Store                store.Store
	LogFunc              func(level, message string, err error)
}

// NewServer creates a new server
func NewServer(opts *ServerOptions) *Server {
	o := &ServerOptions{}
	if opts != nil {
		o = opts
	}

	timeout := DefaultHTTPRequestTimeout
	if o.RequestTimeout > 0 {
		timeout = o.RequestTimeout
	}

	if o.RegistrationTokenTTL < 1 {
		o.RegistrationTokenTTL = DefaultRequestTokenTTL
	}

	return &Server{
		registrationTokenTTL: o.RegistrationTokenTTL,
		store:                o.Store,
		httpClient: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: o.Insecure},
			},
		},
		log: o.LogFunc,
	}
}

// Init intiializes the server
func (c *Server) Init() error {
	if c.initialized {
		return nil
	}

	c.log(LogLevelDebug, "initializing trust server", nil)
	if err := c.store.Init(); err != nil {
		c.log(LogLevelError, "failed to initialize the trust server store", err)
		return err
	}

	if err := c.refreshAllTrusts(); err != nil {
		return err
	}

	return nil
}

// parses the token
func (c *Server) parse(tokenString string) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"]
		if !ok {
			return nil, fmt.Errorf("no key ID found in token")
		}
		jwk := c.trustJWKS.GetKey(kid.(string))
		if jwk == nil {
			return nil, fmt.Errorf("key ID %s not found in the current JWKS", kid.(string))
		}
		return jwk.PublicKey()
	})
}

// Verify parses the token and attempts to verify it with its cached jwks
func (c *Server) Verify(tokenString string) (*jwt.Token, error) {
	token, err := c.parse(tokenString)
	if err == nil {
		return token, nil
	}
	if token == nil {
		return token, err
	}

	kid, ok := token.Header["kid"]
	if !ok {
		return token, fmt.Errorf("no key ID found in token")
	}
	if err := c.refreshTrust(kid.(string)); err != nil {
		return token, err
	}
	return c.parse(tokenString)
}

// NewRegistrationToken issues a new registration token
func (c *Server) NewRegistrationToken() (*types.RegistrationToken, error) {
	c.log(LogLevelDebug, "generating a new registration token", nil)
	if err := c.Init(); err != nil {
		return nil, err
	}

	token := &types.RegistrationToken{
		Token:     uuid.New().String(),
		ExpiresAt: time.Now().Unix() + int64(c.registrationTokenTTL),
	}

	if err := c.store.PutRegistrationToken(token); err != nil {
		c.log(LogLevelError, "failed to put trust registration token", err)
		return nil, err
	}

	return token, nil
}

// removes expired registration tokens
func (c *Server) removeExpiredRegistrationTokens() error {
	c.log(LogLevelDebug, "removing expired and invalid trust registration tokens", nil)
	expired := []string{}
	list, err := c.store.GetRegistrationTokens([]string{})
	if err != nil {
		return err
	}
	for _, token := range list {
		if token.ExpiresAt <= time.Now().Unix() {
			expired = append(expired, token.Token)
		} else if err := token.Validate(); err != nil && token.Token != "" {
			expired = append(expired, token.Token)
		}
	}
	if len(expired) > 0 {
		c.log(LogLevelDebug, fmt.Sprintf("removing the following trust registration tokens: %v", expired), nil)
	}

	return c.store.DeleteRegistrationTokens(expired)
}

// refresh the trust cache
func (c *Server) refreshAllTrusts() error {
	trusts, err := c.store.GetTrusts([]string{})
	if err != nil {
		return err
	}
	newJWKS := &JSONWebKeySet{Keys: []*JSONWebKey{}}
	for _, trust := range trusts {
		if err := trust.Validate(); err == nil && !trust.Disabled {
			jwk, err := c.fetchJWK(trust.URL, trust.KeyID)
			if err != nil {
				continue
			} else if jwk == nil {
				c.log(LogLevelWarn, fmt.Sprintf("failed to find kid: %q JWKS from %s", trust.KeyID, trust.URL), nil)
				continue
			}
			newJWKS.Keys = append(newJWKS.Keys, jwk)
		}
	}
	c.trustJWKS = newJWKS
	return nil
}

// refreshes a single trust
func (c *Server) refreshTrust(keyID string) error {
	trusts, err := c.store.GetTrusts([]string{keyID})
	if err != nil {
		return err
	} else if len(trusts) == 0 {
		return fmt.Errorf("failed to find kid: %q in trust store", keyID)
	}

	trust := trusts[0]
	if err := trust.Validate(); err != nil {
		return err
	}

	jwk, err := c.fetchJWK(trust.URL, trust.KeyID)
	if err != nil {
		return err
	}

	newJWKS := &JSONWebKeySet{Keys: []*JSONWebKey{}}
	for _, key := range c.trustJWKS.Keys {
		if jwk.Kid == keyID {
			newJWKS.Keys = append(newJWKS.Keys, jwk)
		} else {
			newJWKS.Keys = append(newJWKS.Keys, key)
		}
	}
	c.trustJWKS = newJWKS
	return nil
}

// fetches a jwk
func (c *Server) fetchJWK(url, keyID string) (*JSONWebKey, error) {
	resp, err := c.httpClient.Get(url)
	if err != nil {
		c.log(LogLevelError, fmt.Sprintf("failed to get JWKS from %s", url), err)
		return nil, err
	}

	var jwks JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		c.log(LogLevelError, fmt.Sprintf("failed to decode JWKS from %s", url), err)
		return nil, err
	}

	return jwks.GetKey(keyID), nil
}

// HandleIssueRegistrationToken handles the issuing of a registration token
func (c *Server) HandleIssueRegistrationToken(w http.ResponseWriter, r *http.Request) {
	if err := c.Init(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// validate the token was issued by a trusted source
	authHeader := r.Header.Get("Authorization")
	parts := strings.Split(authHeader, "Bearer")
	if len(parts) != 2 {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	tokenString := strings.TrimSpace(parts[1])
	token, err := c.Verify(tokenString)
	if err != nil || token == nil || !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	regToken, err := c.NewRegistrationToken()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(regToken); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

// HandleRegister handles a registration request
func (c *Server) HandleRegister(w http.ResponseWriter, r *http.Request) {
	c.log(LogLevelDebug, "trust registration request recieved", nil)
	if err := c.Init(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// decode and validate the request
	var request types.RegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		c.log(LogLevelError, "failed to decode the trust registration request", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if err := request.Validate(); err != nil {
		c.log(LogLevelError, "trust registration request validation failed", err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}

	// remove expired tokens before looking for the requested token
	if err := c.removeExpiredRegistrationTokens(); err != nil {
		c.log(LogLevelError, "remove expired trust registration tokens failed", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// get the registration token from the newly cleaned store
	tokens, err := c.store.GetRegistrationTokens([]string{request.Token})
	if err != nil || len(tokens) == 0 {
		c.log(LogLevelError, "failed to get trust registration token", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// add the request details to the trust store
	trust := &types.Trust{
		URL:      request.URL,
		KeyID:    request.KeyID,
		Disabled: false,
	}

	if err := c.store.PutTrust(trust); err != nil {
		c.log(LogLevelError, "failed to save trust to store", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// remove the registration token
	if err := c.store.DeleteRegistrationTokens([]string{request.Token}); err != nil {
		c.log(LogLevelError, "failed to remove the trust request token", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// TODO: notify peers of store update

	// attempt to update the trust cache
	if err := c.refreshTrust(request.KeyID); err != nil {
		c.log(LogLevelWarn, "failed to refresh JWKS cache", err)
	}

	w.WriteHeader(http.StatusOK)
}

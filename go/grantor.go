package cot

import (
	"fmt"
	"net/rpc"
	"time"

	"github.com/bhoriuchi/cot/go/types"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
)

// RotateGrantorKeyPair rotates the trustee keypair
func (c *Node) RotateGrantorKeyPair() error {
	var err error
	if c.grantorKeyPair, err = c.ensureKeyPair(GrantorKeyPairSubject, true); err != nil {
		return err
	}
	return nil
}

// fetches a jwk
func (c *Node) fetchJWK(trusteeAddr, keyID string) (*JSONWebKey, error) {
	c.log(LogLevelDebug, fmt.Sprintf("Fetching JWK from %s with key ID %s", trusteeAddr, keyID), nil)
	client, err := rpc.Dial("tcp", trusteeAddr)
	if err != nil {
		c.log(LogLevelError, fmt.Sprintf("Failed to connect to trustee at %s", trusteeAddr), err)
		return nil, err
	}
	defer client.Close()

	jwk := &JSONWebKey{}
	if err := client.Call("NodeRPCServer.GetJWK", &keyID, jwk); err != nil {
		c.log(LogLevelError, "Failed to get JWK", err)
		return nil, err
	}

	return jwk, nil
}

// refreshes a single trust
func (c *Node) refreshTrust(keyID string) error {
	c.log(LogLevelDebug, fmt.Sprintf("Refreshing trust for key ID %s", keyID), nil)

	trust, err := c.findTrust(keyID)
	if err != nil {
		c.log(LogLevelError, fmt.Sprintf("Failed to find trust for key ID %s", keyID), err)
		return err
	} else if trust == nil {
		c.log(LogLevelError, fmt.Sprintf("No trusts matching key ID %s found", keyID), types.ErrKeyIDNotFound)
		return types.ErrKeyIDNotFound
	}

	if err := trust.Validate(); err != nil {
		c.log(LogLevelError, "Invalid trust", err)
		return err
	}

	jwk, err := c.fetchJWK(trust.TrusteeAddr, trust.KeyID)
	if err != nil {
		c.log(LogLevelError, "Failed to fetch JWK", err)
		return err
	} else if jwk == nil {
		return nil
	}

	// create a new JWKS with the updated JWK in it
	keys := []*JSONWebKey{jwk}

	// add all keys not matching the updated one back
	for _, key := range c.trustJWKS.Keys {
		if jwk.Kid != keyID {
			keys = append(keys, key)
		}
	}

	c.trustJWKS = &JSONWebKeySet{Keys: keys}
	return nil
}

// refresh the trust cache
func (c *Node) refreshAllTrusts() error {
	trusts, err := c.getTrusts([]string{})
	if err != nil {
		return err
	}
	newJWKS := &JSONWebKeySet{Keys: []*JSONWebKey{}}
	for _, trust := range trusts {
		if err := trust.Validate(); err == nil && !trust.Disabled {
			jwk, err := c.fetchJWK(trust.TrusteeAddr, trust.KeyID)
			if err != nil {
				c.log(LogLevelError, fmt.Sprintf("Failed to fetch JWKS from %s", trust.TrusteeAddr), err)
				continue
			} else if jwk == nil {
				c.log(LogLevelWarn, fmt.Sprintf("Failed to find kid: %q JWKS from %s", trust.KeyID, trust.TrusteeAddr), nil)
				continue
			}
			newJWKS.Keys = append(newJWKS.Keys, jwk)
		} else {
			c.log(LogLevelWarn, fmt.Sprintf("failed to validate trust %v", trust), err)
		}
	}
	c.trustJWKS = newJWKS
	return nil
}

// parses the token
func (c *Node) parse(tokenString string) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"]
		if !ok {
			return nil, fmt.Errorf("No key ID found in token")
		}

		jwk := c.trustJWKS.GetKey(kid.(string))
		if jwk == nil {
			return nil, fmt.Errorf("Key ID %s not found in the current JWKS", kid.(string))
		}
		return jwk.PublicKey()
	})
}

// Verify parses the token and attempts to verify it with its cached jwks
func (c *Node) Verify(tokenString string) (*jwt.Token, error) {
	token, err := c.parse(tokenString)
	if err == nil {
		return token, nil
	}
	if token == nil {
		return token, err
	}

	kid, ok := token.Header["kid"]
	if !ok {
		return token, fmt.Errorf("No key ID found in token")
	}

	if err := c.refreshTrust(kid.(string)); err != nil {
		c.log(LogLevelError, "failed to refresh trust", err)
		return token, err
	}
	return c.parse(tokenString)
}

// NewGrantToken creates and stores a grant token
func (c *Node) NewGrantToken() (*types.TrustGrantToken, error) {
	c.log(LogLevelDebug, "Generating a new registration token", nil)

	token := &types.TrustGrantToken{
		GrantToken: uuid.New().String(),
		ExpiresAt:  time.Now().Unix() + int64(c.registrationTokenTTL),
	}

	if _, err := c.putTrustGrantToken("", token); err != nil {
		c.log(LogLevelError, "Failed to put trust grant token", err)
		return nil, err
	}

	return token, nil
}

// TODO: OnNotify
// TODO: NotifyPeers
// TODO: Disable/Enable trust

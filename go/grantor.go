package cot

import (
	"fmt"
	"net/rpc"
	"time"

	"github.com/bhoriuchi/cot/go/types"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
)

// fetches a jwk
func (c *Node) fetchJWK(trusteeAddr, keyID string) (*JSONWebKey, error) {
	c.log(LogLevelDebug, fmt.Sprintf("fetching JWK from %s with key ID %s", trusteeAddr, keyID), nil)
	client, err := rpc.Dial("tcp", trusteeAddr)
	if err != nil {
		c.log(LogLevelError, fmt.Sprintf("failed to connect to trustee at %s", trusteeAddr), err)
		return nil, err
	}
	defer client.Close()

	jwk := &JSONWebKey{}
	if err := client.Call("NodeRPCServer.GetJWK", &keyID, jwk); err != nil {
		c.log(LogLevelError, "failed to get JWK", err)
		return nil, err
	}

	return jwk, nil
}

// refreshes a single trust
func (c *Node) refreshTrust(keyID string) error {
	c.log(LogLevelDebug, fmt.Sprintf("refreshing trust for key ID %s", keyID), nil)

	trust, err := c.findTrust(keyID)
	if err != nil {
		c.log(LogLevelError, fmt.Sprintf("failed to find trust for key ID %s", keyID), err)
		return err
	} else if trust == nil {
		c.log(LogLevelError, fmt.Sprintf("no trusts matching key ID %s found", keyID), types.ErrKeyIDNotFound)
		return types.ErrKeyIDNotFound
	}

	if err := trust.Validate(); err != nil {
		c.log(LogLevelError, "invalid trust", err)
		return err
	}

	jwk, err := c.fetchJWK(trust.TrusteeAddr, trust.KeyID)
	if err != nil {
		c.log(LogLevelError, "failed to fetch JWK", err)
		return err
	} else if jwk == nil {
		return nil
	}

	if trust.Issuer != jwk.Issuer {
		c.log(
			LogLevelError,
			fmt.Sprintf(
				"the fetched JWK issuer at %s with key ID %s does not match the trust. expected %q, actual %q",
				trust.TrusteeAddr,
				trust.KeyID,
				trust.Issuer,
				jwk.Issuer,
			),
			types.ErrBadIssuer,
		)
		return types.ErrBadIssuer
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
				c.log(LogLevelError, fmt.Sprintf("failed to fetch JWKS from %s", trust.TrusteeAddr), err)
				continue
			} else if jwk == nil {
				c.log(LogLevelWarn, fmt.Sprintf("failed to find kid: %q JWKS from %s", trust.KeyID, trust.TrusteeAddr), nil)
				continue
			}

			if trust.Issuer != jwk.Issuer {
				c.log(
					LogLevelError,
					fmt.Sprintf("the fetched JWK issuer at %s with key ID %s does not match the trust", trust.TrusteeAddr, trust.KeyID),
					types.ErrBadIssuer,
				)
				return types.ErrBadIssuer
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
		jwk, err := c.validateTokenIssuer(token)
		if err != nil {
			return nil, err
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

	kid, ok := token.Header[JwtKeyIDHeader]
	if !ok {
		return token, fmt.Errorf("no key ID found in token")
	}

	if err := c.refreshTrust(kid.(string)); err != nil {
		c.log(LogLevelError, "failed to refresh trust", err)
		return token, err
	}
	return c.parse(tokenString)
}

// NewGrantToken creates and stores a grant token
func (c *Node) NewGrantToken(issuer string) (*types.TrustGrantToken, error) {
	c.log(LogLevelDebug, "Generating a new registration token", nil)

	if issuer == "" {
		return nil, types.ErrInvalidIssuer
	}

	token := &types.TrustGrantToken{
		GrantToken: uuid.New().String(),
		ExpiresAt:  time.Now().Unix() + int64(c.registrationTokenTTL),
		Issuer:     issuer,
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

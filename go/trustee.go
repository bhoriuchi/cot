package cot

import (
	"fmt"
	"net/rpc"
	"time"

	"github.com/bhoriuchi/cot/go/types"
	"github.com/dgrijalva/jwt-go"
)

// RequestTrust requests a trust from the grantor using a grant token
func (c *Node) RequestTrust(issuer, grantorAddr, grantToken string) error {
	if err := c.Serve(); err != nil {
		return err
	}

	keyPair, ok := c.keyPairs[issuer]
	if !ok {
		return types.ErrUnknownIssuer
	}

	request := &types.TrustRequest{
		GrantToken:  grantToken,
		KeyID:       keyPair.KeyID,
		Issuer:      issuer,
		TrusteeAddr: c.rpcAddr,
	}

	client, err := rpc.Dial("tcp", grantorAddr)
	if err != nil {
		c.log(LogLevelError, fmt.Sprintf("Failed to connect to trust node at %s", grantorAddr), err)
		return err
	}

	defer client.Close()
	return client.Call("NodeRPCServer.GrantTrust", request, nil)
}

// BreakTrust requests a trust break
func (c *Node) BreakTrust(grantorAddr string) error {
	if err := c.Serve(); err != nil {
		return err
	}

	tokenString, err := c.Sign(jwt.MapClaims{})
	if err != nil {
		return err
	}

	client, err := rpc.Dial("tcp", grantorAddr)
	if err != nil {
		c.log(LogLevelError, fmt.Sprintf("Failed to connect to trust node at %s", grantorAddr), err)
		return err
	}

	defer client.Close()
	return client.Call("NodeRPCServer.BreakTrust", &tokenString, nil)
}

// GenerateJWKS generates a JWKS
func (c *Node) GenerateJWKS() (*JSONWebKeySet, error) {
	if err := c.Serve(); err != nil {
		return nil, err
	}

	pairs, err := c.getKeyPairs([]string{})
	if err != nil {
		return nil, err
	}

	keys := []*JSONWebKey{}
	if c.additionalJwkFunc != nil {
		additionalJWKS := c.additionalJwkFunc()
		if additionalJWKS != nil {
			keys = additionalJWKS
		}
	}

	for _, pair := range pairs {
		publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(pair.PublicKey))
		if err != nil {
			c.log(LogLevelError, "Failed to parse public key from keypair", err)
			return nil, err
		}

		jwk, err := NewRS256JSONWebKey(publicKey, pair.KeyID, JwkUseSig, pair.Issuer)
		if err != nil {
			c.log(LogLevelError, "Failed create a new JWK", err)
			return nil, err
		}

		keys = append(keys, jwk)
	}

	return &JSONWebKeySet{Keys: keys}, nil
}

// Sign signs the claims with the client key
func (c *Node) Sign(claims jwt.MapClaims, ttl ...int) (string, error) {
	if err := c.Serve(); err != nil {
		return "", err
	}

	c.log(LogLevelDebug, "Signing a trustee JWT", nil)
	expiresIn := MaxJwtTTL

	if len(ttl) > 0 {
		if ttl[0] > 1 && ttl[0] <= MaxJwtTTL {
			expiresIn = ttl[0]
		}
	}

	issuer, ok := claims[JwtIssuerClaim]
	if !ok {
		return "", types.ErrUnknownIssuer
	}

	keyPair, ok := c.keyPairs[issuer.(string)]
	if !ok {
		return "", types.ErrUnknownIssuer
	}

	if err := keyPair.Validate(); err != nil {
		return "", err
	}

	// add expiration
	claims[JwtExpiresAtClaim] = time.Now().Unix() + int64(expiresIn)
	header := map[string]interface{}{JwtKeyIDHeader: keyPair.KeyID}

	return SignRS256WithClaims([]byte(keyPair.PrivateKey), claims, header)
}

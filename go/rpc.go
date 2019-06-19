package cot

import (
	"fmt"
	"net"
	"net/rpc"

	"github.com/bhoriuchi/cot/go/types"
)

var trueValue = true
var falseValue = false

// NodeRPCServer node rpc server
type NodeRPCServer struct {
	node *Node
}

// listens for rpc connectins
func (c *NodeRPCServer) serve() error {
	c.node.log(LogLevelDebug, fmt.Sprintf("Starting trust RPC on %s", c.node.rpcAddr), nil)
	handler := rpc.NewServer()
	handler.Register(c)
	ln, err := net.Listen("tcp", c.node.rpcAddr)
	if err != nil {
		c.node.log(LogLevelError, "Failed to create trust RPC listener", err)
		return err
	}
	go func() {
		for {
			cxn, err := ln.Accept()
			if err != nil {
				c.node.log(LogLevelError, "Failed to accept trust RPC connection", err)
				return
			}
			go handler.ServeConn(cxn)
		}
	}()
	c.node.log(LogLevelDebug, fmt.Sprintf("SUCCESS! Started trust RPC on %s", c.node.rpcAddr), nil)
	return nil
}

// GrantTrust grants a trust request if it is valid
func (c *NodeRPCServer) GrantTrust(request *types.TrustRequest, reply *bool) error {
	c.node.log(LogLevelDebug, "GrantTrust request recieved", nil)

	if err := request.Validate(); err != nil {
		return err
	}

	// remove invalid tokens
	if err := c.node.removeInvalidTrustGrantTokens(); err != nil {
		c.node.log(LogLevelError, "Failed to remove invalid grant tokens", err)
		return err
	}

	// search for grant token
	token, err := c.node.findTrustGrantToken(request.GrantToken)
	if err != nil || token == nil {
		c.node.log(LogLevelError, "Trust grant token not found", err)
		return err
	}

	// look for existing trust with keyid
	trustID := ""
	trust, err := c.node.findTrust(request.KeyID)
	if err == nil && trust != nil {
		c.node.log(LogLevelDebug, "Found existing trust", nil)
		trustID = trust.ID
	}

	// store the trust
	trust = &types.Trust{
		ID:          trustID,
		TrusteeAddr: request.TrusteeAddr,
		KeyID:       request.KeyID,
		Disabled:    false,
	}

	trustID, err = c.node.putTrust(trustID, trust)
	if err != nil {
		c.node.log(LogLevelError, "Failed to put trust", err)
		return err
	}

	// remove the used grant token
	if err := c.node.store.DeleteTrustGrantTokens([]string{token.ID}); err != nil {
		c.node.log(LogLevelError, "Failed to delete trust grant token", err)
		return err
	}

	// refresh the trust for the key id
	if err := c.node.refreshTrust(request.KeyID); err != nil {
		c.node.log(LogLevelError, fmt.Sprintf("Failed to refresh trust from trustee %s, removing trust", request.TrusteeAddr), err)
		if err := c.node.store.DeleteTrusts([]string{trustID}); err != nil {
			c.node.log(LogLevelError, fmt.Sprintf("Failed to remove trust with key ID %s, it should be manually deleted", request.KeyID), err)
		}
		return err
	}

	c.node.NotifyPeers()
	if reply != nil {
		*reply = trueValue
	}
	return nil
}

// GetJWK gets a jwk for the specified key id
func (c *NodeRPCServer) GetJWK(keyID *string, reply *JSONWebKey) error {
	c.node.log(LogLevelDebug, fmt.Sprintf("Request for trustee jwk with key ID %s", *keyID), nil)
	jwks, err := c.node.GenerateJWKS()
	if err != nil {
		return err
	}
	jwk := jwks.GetKey(*keyID)
	*reply = *jwk
	return nil
}

// IssueGrantToken issues a grant token
func (c *NodeRPCServer) IssueGrantToken(tokenString *string, reply *types.TrustGrantToken) error {
	token, err := c.node.Verify(*tokenString)
	if err != nil {
		return err
	} else if !token.Valid {
		return types.ErrInvalidJwtToken
	}

	grantToken, err := c.node.NewGrantToken()
	if err != nil {
		return err
	}

	*reply = *grantToken
	return nil
}

// BreakTrust breaks the trust by removing it
func (c *NodeRPCServer) BreakTrust(tokenString *string, reply *bool) error {
	token, err := c.node.Verify(*tokenString)
	if err != nil {
		return err
	} else if !token.Valid {
		return types.ErrInvalidJwtToken
	}

	kid, ok := token.Header["kid"]
	if !ok {
		return types.ErrKeyIDNotFound
	}

	trust, err := c.node.findTrust(kid.(string))
	if err != nil {
		return err
	} else if trust == nil {
		return ErrNotFound
	}

	if reply != nil {
		*reply = trueValue
	}
	return c.node.store.DeleteTrusts([]string{trust.ID})
}

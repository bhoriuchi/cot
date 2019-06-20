package cot

import (
	"encoding/json"
	"fmt"
	"net"
	"net/rpc"
	"time"

	"github.com/bhoriuchi/cot/go/store"
	"github.com/bhoriuchi/cot/go/types"
)

var trueValue = true
var falseValue = false

// NodeRPC node rpc server
type NodeRPC struct {
	node *Node
	conn net.Conn
}

// listens for rpc connectins
func (c *Node) rpc() error {
	c.log(LogLevelDebug, fmt.Sprintf("Starting trust RPC on %s", c.rpcAddr), nil)
	ln, err := net.Listen("tcp", c.rpcAddr)
	if err != nil {
		c.log(LogLevelError, "Failed to create trust RPC listener", err)
		return err
	}
	go func() {
		for {
			cxn, err := ln.Accept()
			if err != nil {
				c.log(LogLevelError, "Failed to accept trust RPC connection", err)
				return
			}
			node := &NodeRPC{
				node: c,
				conn: cxn,
			}
			handler := rpc.NewServer()
			handler.Register(node)
			go handler.ServeConn(cxn)
		}
	}()
	c.log(LogLevelDebug, fmt.Sprintf("SUCCESS! Started trust RPC on %s", c.rpcAddr), nil)
	return nil
}

// GrantTrust grants a trust request if it is valid
func (c *NodeRPC) GrantTrust(request *types.TrustRequest, reply *bool) error {
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

	if request.Issuer != token.Issuer {
		return fmt.Errorf("the requested issuer does not match the issuer specified in the grant token")
	}

	// store the trust
	trust = &types.Trust{
		ID:          trustID,
		TrusteeAddr: request.TrusteeAddr,
		KeyID:       request.KeyID,
		Issuer:      request.Issuer,
		Disabled:    false,
	}

	trustID, err = c.node.putTrust(trustID, trust)
	if err != nil {
		c.node.log(LogLevelError, "Failed to put trust", err)
		return err
	}

	// remove the used grant token
	if err := c.node.deleteTrustGrantToken(token.ID); err != nil {
		c.node.log(LogLevelError, "Failed to delete trust grant token", err)
		return err
	}

	// refresh the trust for the key id
	if err := c.node.refreshTrust(request.KeyID); err != nil {
		c.node.log(LogLevelError, fmt.Sprintf("Failed to refresh trust from trustee %s, removing trust", request.TrusteeAddr), err)
		if err := c.node.deleteTrust(trustID); err != nil {
			c.node.log(LogLevelError, fmt.Sprintf("Failed to remove trust with key ID %s, it should be manually deleted", request.KeyID), err)
		}
		return err
	}

	// set the reply
	if reply != nil {
		*reply = trueValue
	}
	return nil
}

// GetJWK gets a jwk for the specified key id
func (c *NodeRPC) GetJWK(keyID *string, reply *JSONWebKey) error {
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
// the token is automatically assigned the same issuer as the requesting token
func (c *NodeRPC) IssueGrantToken(tokenString *string, reply *types.TrustGrantToken) error {
	token, err := c.node.Verify(*tokenString)
	if err != nil {
		return err
	} else if !token.Valid {
		return types.ErrInvalidJwtToken
	}

	// look up trust key id and find allowed issuers
	kid := token.Header[JwtKeyIDHeader]
	trust, err := c.node.findTrust(kid.(string))
	if err != nil {
		return err
	}

	grantToken, err := c.node.NewGrantToken(trust.Issuer)
	if err != nil {
		return err
	}

	*reply = *grantToken
	return nil
}

// BreakTrust breaks the trust by removing it
func (c *NodeRPC) BreakTrust(tokenString *string, reply *bool) error {
	token, err := c.node.Verify(*tokenString)
	if err != nil {
		return err
	} else if !token.Valid {
		return types.ErrInvalidJwtToken
	}

	kid, ok := token.Header[JwtKeyIDHeader]
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

	if err := c.node.deleteTrust(trust.ID); err != nil {
		return err
	}

	if err := c.node.RefreshAllTrusts(); err != nil {
		c.node.log(LogLevelError, "failed to refresh trusts", err)
	}

	return nil
}

// OnNotify handles a notify rpc
func (c *NodeRPC) OnNotify(notification *types.Notification, reply *bool) error {
	// check for peer address
	remoteAddr := c.conn.RemoteAddr()
	if !c.node.isPeer(fmt.Sprintf("%v", remoteAddr)) {
		c.node.log(LogLevelDebug, fmt.Sprintf("non-peer node notification recieved from %v", remoteAddr), nil)
		return nil
	}

	// check if the notification has already been processed
	if _, ok := c.node.notifications[notification.ID]; !ok {
		c.node.log(LogLevelDebug, fmt.Sprintf("new notification %s", notification.ID), nil)
	} else {
		c.node.log(LogLevelDebug, fmt.Sprintf("already processed notification %s", notification.ID), nil)
		return nil
	}

	// update notifications to remove expired
	updatedNotifications := map[string]int64{}
	for id, expiresAt := range c.node.notifications {
		if expiresAt > time.Now().Unix() {
			updatedNotifications[id] = expiresAt
		}
	}
	updatedNotifications[notification.ID] = notification.ExpiresAt
	c.node.notifications = updatedNotifications

	// forward the event to current node peers
	// this allows peers to join any node
	c.node.notifyPeers(notification)

	// handle the updates
	switch notification.Topic {
	case TopicTrustChange:
		if c.node.store.Type() == store.StoreTypeDistributed {
			switch notification.Event {
			case EventTrustDelete:
				if err := c.node.store.DeleteTrusts([]string{notification.Data}); err != nil {
					c.node.log(LogLevelError, fmt.Sprintf("notify handler failed to remove trust %s", notification.Data), err)
				}

			case EventTrustPut:
				data := &types.StoredData{}
				if err := json.Unmarshal([]byte(notification.Data), data); err != nil {
					c.node.log(LogLevelError, "notify handler failed to unmarshal trust", err)
				}
				if _, err := c.node.store.PutTrust(data); err != nil {
					c.node.log(LogLevelError, fmt.Sprintf("notify handler failed to put trust %s", data.ID), err)
				}
			}
		}

		// refresh all the trusts
		if err := c.node.RefreshAllTrusts(); err != nil {
			c.node.log(LogLevelError, "notify handler failed to refresh all trusts", err)
		}

	case TopicKeyPairChange:
		if c.node.store.Type() == store.StoreTypeDistributed {
			switch notification.Event {
			case EventKeyPairDelete:
				if err := c.node.store.DeleteKeyPairs([]string{notification.Data}); err != nil {
					c.node.log(LogLevelError, fmt.Sprintf("notify handler failed to remove keypair %s", notification.Data), err)
				}

			case EventKeyPairPut:
				data := &types.StoredData{}
				if err := json.Unmarshal([]byte(notification.Data), data); err != nil {
					c.node.log(LogLevelError, "notify handler failed to unmarshal keypair", err)
				}
				if _, err := c.node.store.PutKeyPair(data); err != nil {
					c.node.log(LogLevelError, fmt.Sprintf("notify handler failed to put keypair %s", data.ID), err)
				}
			}
		}

		// refresh all the key pairs
		if err := c.node.refreshKeyPairs(); err != nil {
			c.node.log(LogLevelError, "notify handler failed to refresh all keypairs", err)
		}

	case TopicGrantTokenChange:
		if c.node.store.Type() == store.StoreTypeDistributed {
			switch notification.Event {
			case EventGrantTokenDelete:
				if err := c.node.store.DeleteTrustGrantTokens([]string{notification.Data}); err != nil {
					c.node.log(LogLevelError, fmt.Sprintf("notify handler failed to remove trust grant token %s", notification.Data), err)
				}

			case EventGrantTokenPut:
				data := &types.StoredData{}
				if err := json.Unmarshal([]byte(notification.Data), data); err != nil {
					c.node.log(LogLevelError, "notify handler failed to unmarshal grant token", err)
				}
				if _, err := c.node.store.PutTrustGrantToken(data); err != nil {
					c.node.log(LogLevelError, fmt.Sprintf("notify handler failed to put grant token %s", data.ID), err)
				}

			case EventGrantTokenBulkDelete:
				if err := c.node.removeInvalidTrustGrantTokens(); err != nil {
					c.node.log(LogLevelError, "failed to remove expired or invalid trust grant tokens", err)
				}
			}
		}
	}

	return nil
}

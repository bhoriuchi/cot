package cot

import (
	"encoding/json"
	"fmt"

	"github.com/bhoriuchi/cot/go/types"
	"gopkg.in/square/go-jose.v2"
)

// unprepareData converts stored data to a type and optinally decrypts
func (c *Node) unprepareData(data *types.StoredData, target interface{}) error {
	if data.Encrypted {
		if c.encryptionKey == "" {
			return fmt.Errorf("cannot decrypt encrypted store data without encryption key")
		}
		jwe, err := jose.ParseEncrypted(data.Data.(string))
		if err != nil {
			return err
		}

		j, err := jwe.Decrypt([]byte(c.encryptionKey))
		if err != nil {
			return err
		}

		return json.Unmarshal(j, target)
	}

	j, err := json.Marshal(data.Data)
	if err != nil {
		return err
	}

	return json.Unmarshal(j, target)
}

// prepareData prepares data to be stored by converting it to
// a StoredData type and optinally encrypting the data
func (c *Node) prepareData(id string, data interface{}) (*types.StoredData, error) {
	if c.encryptionKey == "" {
		storedData := &types.StoredData{
			Data:      data,
			Encrypted: false,
		}
		return storedData, nil
	}

	j, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	enc, err := jose.NewEncrypter(
		jose.A128CBC_HS256,
		jose.Recipient{
			Algorithm: jose.A128GCMKW,
			Key:       []byte(c.encryptionKey),
		},
		nil,
	)

	if err != nil {
		return nil, err
	}

	jwe, err := enc.Encrypt(j)
	if err != nil {
		return nil, err
	}

	storedData := &types.StoredData{
		ID:        id,
		Data:      jwe.FullSerialize(),
		Encrypted: true,
	}

	return storedData, nil
}

// gets storeddata from the store and converts it to keypairs
func (c *Node) getKeyPairs(ids []string) ([]*types.KeyPair, error) {
	pairs := []*types.KeyPair{}
	pairData, err := c.store.GetKeyPairs(ids)
	if err != nil {
		return nil, err
	}

	for _, data := range pairData {
		var keyPair types.KeyPair
		if err := c.unprepareData(data, &keyPair); err != nil {
			return nil, err
		}
		keyPair.ID = data.ID
		pairs = append(pairs, &keyPair)
	}

	return pairs, nil
}

// gets trusts from the store
func (c *Node) getTrusts(ids []string) ([]*types.Trust, error) {
	trusts := []*types.Trust{}
	trustData, err := c.store.GetTrusts(ids)
	if err != nil {
		return nil, err
	}

	for _, data := range trustData {
		var trust types.Trust
		if err := c.unprepareData(data, &trust); err != nil {
			return nil, err
		}
		trust.ID = data.ID
		trusts = append(trusts, &trust)
	}

	return trusts, nil
}

// gets storeddata from the store and converts it to keypairs
func (c *Node) getTrustGrantTokens(ids []string) ([]*types.TrustGrantToken, error) {
	tokens := []*types.TrustGrantToken{}
	tokenData, err := c.store.GetTrustGrantTokens(ids)
	if err != nil {
		return nil, err
	}

	for _, data := range tokenData {
		var token types.TrustGrantToken
		if err := c.unprepareData(data, &token); err != nil {
			return nil, err
		}
		token.ID = data.ID
		tokens = append(tokens, &token)
	}

	return tokens, nil
}

// finds a key pair by issuer
func (c *Node) findKeyPair(issuer string) (*types.KeyPair, error) {
	pairs, err := c.getKeyPairs([]string{})
	if err != nil {
		return nil, err
	}
	for _, pair := range pairs {
		if pair.Issuer == issuer {
			return pair, nil
		}
	}
	return nil, ErrNotFound
}

// finds a trust by keyID
func (c *Node) findTrust(keyID string) (*types.Trust, error) {
	trusts, err := c.getTrusts([]string{})
	if err != nil {
		return nil, err
	}
	for _, trust := range trusts {
		if trust.KeyID == keyID {
			return trust, nil
		}
	}
	return nil, ErrNotFound
}

// finds a grantToken by token
func (c *Node) findTrustGrantToken(grantToken string) (*types.TrustGrantToken, error) {
	tokens, err := c.getTrustGrantTokens([]string{})
	if err != nil {
		return nil, err
	}
	for _, token := range tokens {
		if token.GrantToken == grantToken {
			return token, nil
		}
	}
	return nil, ErrNotFound
}

// puts a key pair in the store
func (c *Node) putKeyPair(id string, keyPair *types.KeyPair) (string, error) {
	data, err := c.prepareData(id, keyPair)
	if err != nil {
		return id, err
	}

	id, err = c.store.PutKeyPair(data)
	if err != nil {
		c.log(LogLevelError, "Failed to put trust client key pair", err)
		return id, err
	}

	return id, nil
}

// puts a trust in the store
func (c *Node) putTrust(id string, trust *types.Trust) (string, error) {
	data, err := c.prepareData(id, trust)
	if err != nil {
		return id, err
	}

	id, err = c.store.PutTrust(data)
	if err != nil {
		c.log(LogLevelError, "Failed to put trust client trust", err)
		return id, err
	}

	return id, nil
}

// puts a trust grant token in the store
func (c *Node) putTrustGrantToken(id string, grantToken *types.TrustGrantToken) (string, error) {
	data, err := c.prepareData(id, grantToken)
	if err != nil {
		return id, err
	}

	id, err = c.store.PutTrustGrantToken(data)
	if err != nil {
		c.log(LogLevelError, "Failed to put trust grant token", err)
		return id, err
	}

	return id, nil
}

// removes invalid trust grant tokens
func (c *Node) removeInvalidTrustGrantTokens() error {
	c.log(LogLevelDebug, "Removing expired and invalid trust grant tokens", nil)
	expired := []string{}
	list, err := c.getTrustGrantTokens([]string{})
	if err != nil {
		return err
	}
	for _, token := range list {
		if err := token.Validate(); err != nil {
			c.log(LogLevelDebug, fmt.Sprintf("Removing invalid token: %v", err), nil)
			expired = append(expired, token.GrantToken)
		}
	}

	return c.store.DeleteTrustGrantTokens(expired)
}

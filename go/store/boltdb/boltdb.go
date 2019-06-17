package boltdb

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/bhoriuchi/cot/go/store"
	"github.com/bhoriuchi/cot/go/types"
	bolt "go.etcd.io/bbolt"
)

// buckets and things
const (
	DefaultRegistrationBucket = "registration"
	DefaultKeyPairBucket      = "keypair"
	DefaultTrustBucket        = "trust"
	DefaultTrustClientBucket  = "trust_client"
)

// Options store options
type Options struct {
	Database           string
	RegistrationBucket string
	KeyPairBucket      string
	TrustBucket        string
	TrustClientBucket  string
}

// Store a boltdb store for the trust
type Store struct {
	database           string
	registrationBucket []byte
	keypairBucket      []byte
	trustBucket        []byte
	trustClientBucket  []byte
}

// TrustClientConfigData a json wrapper for putting config data
type TrustClientConfigData struct {
	Data string `json:"data" yaml:"data"`
}

// NewStore creates a new store
func NewStore(opts *Options) *Store {
	o := &Options{}
	if opts != nil {
		o = opts
	}
	if o.RegistrationBucket == "" {
		o.RegistrationBucket = DefaultRegistrationBucket
	}
	if o.KeyPairBucket == "" {
		o.KeyPairBucket = DefaultKeyPairBucket
	}
	if o.TrustBucket == "" {
		o.TrustBucket = DefaultTrustBucket
	}
	if o.TrustClientBucket == "" {
		o.TrustClientBucket = DefaultTrustClientBucket
	}

	return &Store{
		database:           o.Database,
		registrationBucket: []byte(o.RegistrationBucket),
		keypairBucket:      []byte(o.KeyPairBucket),
		trustBucket:        []byte(o.TrustBucket),
		trustClientBucket:  []byte(o.TrustClientBucket),
	}
}

// Type returns the store type
func (c *Store) Type() store.Type {
	return store.StoreTypeDistributed
}

// Init inits the store
func (c *Store) Init() error {
	if c.database == "" {
		return fmt.Errorf("no database file specified")
	}

	buckets := [][]byte{
		c.registrationBucket,
		c.keypairBucket,
		c.trustBucket,
		c.trustClientBucket,
	}

	// get the absolute path for the file
	absPath, err := filepath.Abs(c.database)
	if err != nil {
		return err
	}
	c.database = absPath

	// ensure the directory path exists
	if err := os.MkdirAll(filepath.Dir(absPath), 0755); err != nil {
		return err
	}

	// open the db and ensure the buckets
	db, err := bolt.Open(c.database, 0666, nil)
	if err != nil {
		return err
	}
	defer db.Close()
	return db.Update(func(tx *bolt.Tx) error {
		for _, bucket := range buckets {
			if _, err := tx.CreateBucketIfNotExists(bucket); err != nil {
				return err
			}
		}
		return nil
	})
}

// put puts an item in the database
func (c *Store) put(data interface{}, key, bucket []byte) error {
	if data == nil {
		return fmt.Errorf("no %s provied to put", bucket)
	}
	value, err := json.Marshal(data)
	if err != nil {
		return err
	}

	db, err := bolt.Open(c.database, 0666, nil)
	if err != nil {
		return err
	}
	defer db.Close()

	return db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		return b.Put(key, value)
	})
}

// deletes a list of keys from the database
func (c *Store) del(ids []string, bucket []byte) error {
	if len(ids) == 0 {
		return nil
	}

	db, err := bolt.Open(c.database, 0666, nil)
	if err != nil {
		return err
	}
	defer db.Close()

	return db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		for _, id := range ids {
			if err := b.Delete([]byte(id)); err != nil {
				return err
			}
		}
		return nil
	})
}

// returns a list of values
func (c *Store) list(ids []string, bucket []byte) ([]byte, error) {
	db, err := bolt.Open(c.database, 0666, nil)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	idMap := map[string]string{}
	for _, id := range ids {
		idMap[id] = id
	}

	values := [][]byte{}
	if err := db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucket)
		return bucket.ForEach(func(key, data []byte) error {
			// check if the idmap contains the key or there were no ids specified
			if _, ok := idMap[string(key)]; ok || len(ids) == 0 {
				values = append(values, data)
			}
			return nil
		})
	}); err != nil {
		return nil, err
	}

	if len(values) == 0 {
		return []byte("[]"), nil
	}

	arr := append(
		[]byte("["),
		bytes.Join(
			append(values, []byte("]")),
			[]byte(","),
		)...,
	)
	return arr, nil
}

// PutRegistrationToken puts a registration token
func (c *Store) PutRegistrationToken(token *types.RegistrationToken) error {
	return c.put(token, []byte(token.Token), c.registrationBucket)
}

// DeleteRegistrationTokens puts a registration token
func (c *Store) DeleteRegistrationTokens(tokens []string) error {
	return c.del(tokens, c.registrationBucket)
}

// GetRegistrationTokens gets all the registration tokens
func (c *Store) GetRegistrationTokens(ids []string) ([]*types.RegistrationToken, error) {
	list, err := c.list(ids, c.registrationBucket)
	if err != nil {
		return nil, err
	}

	var tokens []*types.RegistrationToken
	if err := json.Unmarshal(list, &tokens); err != nil {
		return nil, err
	}
	return tokens, nil
}

// PutKeyPair puts a keypair
func (c *Store) PutKeyPair(keypair *types.KeyPair) error {
	return c.put(keypair, []byte(keypair.KeyID), c.keypairBucket)
}

// DeleteKeyPairs deletes a list of key pairs
func (c *Store) DeleteKeyPairs(ids []string) error {
	return c.del(ids, c.keypairBucket)
}

// GetKeyPairs gets all keypairs
func (c *Store) GetKeyPairs(ids []string) ([]*types.KeyPair, error) {
	list, err := c.list(ids, c.keypairBucket)
	if err != nil {
		return nil, err
	}

	var keypairs []*types.KeyPair
	if err := json.Unmarshal(list, &keypairs); err != nil {
		return nil, err
	}
	return keypairs, nil
}

// PutTrust puts a trust
func (c *Store) PutTrust(trust *types.Trust) error {
	return c.put(trust, []byte(trust.KeyID), c.trustBucket)
}

// DeleteTrusts deletes a list of trusts
func (c *Store) DeleteTrusts(ids []string) error {
	return c.del(ids, c.trustBucket)
}

// GetTrusts gets all the trusts
func (c *Store) GetTrusts(ids []string) ([]*types.Trust, error) {
	list, err := c.list(ids, c.trustBucket)
	if err != nil {
		return nil, err
	}

	var trusts []*types.Trust
	if err := json.Unmarshal(list, &trusts); err != nil {
		return nil, err
	}
	return trusts, nil
}

// PutTrustClientConfig puts a config in the trust client config bucket
func (c *Store) PutTrustClientConfig(key, value string) error {
	data := &TrustClientConfigData{Data: value}
	return c.put(data, []byte(key), c.trustClientBucket)
}

// GetTrustClientConfig gets a config from the trust client config bucket
func (c *Store) GetTrustClientConfig(key string) (string, bool, error) {
	list, err := c.list([]string{key}, c.trustClientBucket)
	if err != nil {
		return "", false, err
	}

	var data []*TrustClientConfigData
	if err := json.Unmarshal(list, &data); err != nil {
		return "", true, err
	}

	if len(data) == 0 {
		return "", false, nil
	}

	clientConfig := data[0].Data
	return clientConfig, true, nil
}

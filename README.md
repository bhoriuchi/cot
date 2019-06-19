# cot
Circle of Trust - Maintain trusts between services using JWT

Circle of Trust works like this

## Terminology

* `Node` a combined Grantor and Trustee
* `Grantor` grants trusts to allow access to its resources
* `Trustee` requests trust from grantor in order to access its resources
* `TrustGrantToken` one time use token that establishes a trust between nodes
* `Trust` an RPC Address and Key ID to trust for public key
* `KeyPair` a public and private key pair with a subject
* `Persistent Store` where Trusts, KeyPairs, and TrustGrantTokens are stored

## Registration

Any node with a valid token can request a registration token on behalf of a new node. The first node will need its registration token manually generated.

1. The Grantor issues a one time use TrustGrantToken
2. The Trustee request a TrustGrant by sending a TrustGrantToken, its RPC Address, and the Key ID (kid) of the public key to use for verifying requests
3. The Grantor acceps the TrustGrantToken if it is valid, stores the Key ID with the RPC Address in its persistent store. Additionally the Grantor will lookup and cache the JWK identified by the Key ID.

The Grantor will now trust any request that contains a JWT that can be verified by the public key identified by the Key ID.

## Key Rotation

Since keys should be rotated, the process for key rotation is as follows

1. The Trustee rotates its key but keeps the same key ID.
2. The first request after rotation will be signed with a new key and cause an authentication failure on requests to the Grantor.
3. The Grantor will interpret the authentication failure as a key rotation and refresh the key from the Trustee and try to re-verify the token with the new key. If the verification still fails, the request fails. If successful the resource is returned.

## Disabling Trust

A trust can be temporarily or indefinitely disabled by the Grantor by marking it as disabled in the persistent store

## Breaking Trust

Removing the trust from the Grantors persistent store breaks it. This can be initiated by the Trustee or Grantor. The trustee must send a signed token to the BreakTrust procedure and the KeyID from the token will be used to break the trust.
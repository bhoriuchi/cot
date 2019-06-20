# cot
Circle of Trust - Maintain trusts between services using JWT

Circle of Trust works like this

## Terminology

* `Grantor` grants trusts to allow access to its resources
* `Trustee` requests trust from grantor in order to access its resources
* `Node` a combination of a Grantor and Trustee
* `TrustGrantToken` one time use token that establishes a trust between nodes
* `Trust` an RPC Address and Key ID to trust for public key
* `KeyPair` a public and private key pair with a subject
* `Persistent Store` where Trusts, KeyPairs, and TrustGrantTokens are stored
* `KeyID` unique identifier for a JSON Web Key
* `Issuer ID` an identifier for the source a JSON Web Token was issued from

## Registration

Any node with a valid token can request a registration token on behalf of a new node for the same issuer ID. The first node will need its registration token manually generated.

1. The Grantor issues a one time use TrustGrantToken containing a token, expiration date, and issuer ID
2. The Trustee requests a TrustGrant by sending a TrustGrantToken, its RPC Address, issuer ID, and the Key ID (kid) of the public key to use for verifying requests
3. The Grantor acceps the TrustGrantToken if it is valid (token exists in the persistent store and the issuer matches the grant token), stores the Key ID with the RPC Address and issuer ID in its persistent store. Additionally the Grantor will lookup and cache the JWK identified by the Key ID and verify that the issuer IDs match the trust

The Grantor will now trust any request that contains a JWT that can be verified by the public key identified by the Key ID.

A valid JWT contains a key ID that can found in the current trusts who's JWK identifies the issuer defined in the trust. This prevents trustees from issuing tokens for issuers outside the ones it has been trusted to issue. The issuer is added to all token claims with the sign method.

## Key Rotation

Since keys should be rotated periodically, the process for key rotation is as follows

1. The Trustee rotates its key but keeps the same key ID.
2. The first request after rotation will be signed with a new key and cause a validation failure on requests to the Grantor (assuming the Verify function is being used on the node).
3. The Grantor will interpret the validation failure as a key rotation and refresh the key from the Trustee and try to re-verify the token with the new key. If the verification still fails, the verification fails. If successful the verification succeeds.

## Disabling Trust

A trust can be temporarily or indefinitely disabled by the Grantor by marking it as disabled in the persistent store

## Breaking Trust

Removing the trust from the Grantors persistent store breaks it. This can be initiated by the Trustee or Grantor. The trustee must send a signed token to the BreakTrust procedure and the KeyID from the token will be used to break the trust.

## Encryption

Encryption should be enabled when possible. Circle Of Trust uses JWE to store encrypted data with a shared key.
# cot
Circle of Trust - Maintain trusts between services using JWT

Circle of Trust works like this

## Registration

Any node with a valid token can request a registration token on behalf of a new node. The first node will need its registration token manually generated.

1. The resource server issues a one time use registration token
2. The client server performs a registration by sending the registration token, its JWKS endpoint, and the key ID (kid) it will use for requests
3. The resource server acceps the JWT verification key, stores the key ID with the JWKS endpoint in its local store, and sends back an ok response. Additionally the resource server will lookup and cache the JWK identified by the key ID.

The resource server will now trust any request that contains a JWT that can be verified by the verification key.

## Key Rotation

Since keys should be rotated, the process for key rotation is as follows

1. The client server rotates its key but keeps the same key ID.
2. The first request after rotation will be signed with a new key and cause an authentication failure on the resource server.
3. The resource server will interpret the authentication failure as a key rotation and refresh the key from the JWKS endpoint and try to re-verify the token with the new key. If the verification still fails, the request fails. If successful the resource is returned.

## Disabling Trust

A trust can be temporarily or indefinitely disabled by the resource server by marking it as disabled in the local store

## Breaking Trust

Removing the trust between the resource and requesting server is as simple as removing the client record from the resource server store
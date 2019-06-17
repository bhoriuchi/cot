package cot

import "github.com/dgrijalva/jwt-go"

// SignRS256WithClaims signs claims with RS256
func SignRS256WithClaims(privateKeyPEM []byte, claims jwt.MapClaims) (string, error) {
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		return "", err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(privateKey)
}

// ParseRS256 parses an RS256 tokenString
func ParseRS256(publicKeyPEM []byte, tokenString string) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return jwt.ParseRSAPublicKeyFromPEM(publicKeyPEM)
	})
}

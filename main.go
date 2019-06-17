package main

import (
	"log"
	"os"
	"path"

	cot "github.com/bhoriuchi/cot/go"
)

func main() {
	dir, err := os.Getwd()
	if err != nil {
		log.Fatalln(err)
	}

	client := cot.NewClient(path.Join(dir, "trust.yaml"), "http://localhost/cert/trust")
	if err := client.Init(); err != nil {
		if err != nil {
			log.Fatalln(err)
		}

	}
	/*
		secret := "sauce"
		privteKeyPEM, publicKeyPEM, err := cot.GenerateRSAKeyPair()
		if err != nil {
			log.Fatalln(err)
		}
		privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privteKeyPEM)
		if err != nil {
			log.Fatalln(err)
		}

		fmt.Println(string(publicKeyPEM))

		publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyPEM)
		if err != nil {
			log.Fatalln(err)
		}

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"data": secret,
		})
		tokenString, err := token.SignedString(privateKey)
		if err != nil {
			log.Fatalln(err)
		}

		t, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return publicKey, nil
		})
		if err != nil {
			log.Fatalln(err)
		}
		fmt.Println(t)

		key, _ := cot.NewRS256JSONWebKey(publicKey)
		j, _ := json.MarshalIndent(key, "", "  ")
		fmt.Println(string(j))
	*/
}

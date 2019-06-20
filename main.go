package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	cot "github.com/bhoriuchi/cot/go"
	"github.com/dgrijalva/jwt-go"

	"github.com/bhoriuchi/cot/go/store/boltdb"
	"github.com/spf13/cobra"
)

var addr string
var encKey string
var rpcAddr string
var signedData string
var storeFile string
var grantToken string
var grantorAddr string
var serverMode bool
var clientMode bool

var rootCmd = &cobra.Command{}

var listCmd = &cobra.Command{
	Use: "list",
}

var listTrustCmd = &cobra.Command{
	Use: "trust",
	Run: func(cmd *cobra.Command, args []string) {
		store := boltdb.NewStore(&boltdb.Options{Database: storeFile})
		node := cot.NewNode(&cot.NodeOptions{
			CLIMode:       true,
			EncryptionKey: encKey,
			Store:         store,
			LogFunc:       logFunc,
		})

		if err := node.Serve(); err != nil {
			log.Fatalln(fmt.Sprintf("FATAL: %v", err))
		}

		list, err := node.ListTrusts()
		if err != nil {
			log.Fatalln(fmt.Sprintf("FATAL: %v", err))
		}

		j, err := json.MarshalIndent(list, "", "  ")
		if err != nil {
			log.Fatalln(fmt.Sprintf("FATAL: %v", err))
		}

		log.Printf("%s\n", j)
	},
}

var listKeyPairCmd = &cobra.Command{
	Use: "keypair",
	Run: func(cmd *cobra.Command, args []string) {
		store := boltdb.NewStore(&boltdb.Options{Database: storeFile})
		node := cot.NewNode(&cot.NodeOptions{
			CLIMode:       true,
			EncryptionKey: encKey,
			Store:         store,
			LogFunc:       logFunc,
		})

		if err := node.Serve(); err != nil {
			log.Fatalln(fmt.Sprintf("FATAL: %v", err))
		}

		list, err := node.ListKeyPairs()
		if err != nil {
			log.Fatalln(fmt.Sprintf("FATAL: %v", err))
		}

		j, err := json.MarshalIndent(list, "", "  ")
		if err != nil {
			log.Fatalln(fmt.Sprintf("FATAL: %v", err))
		}

		log.Printf("%s\n", j)
	},
}

var listGrantTokenCmd = &cobra.Command{
	Use: "token",
	Run: func(cmd *cobra.Command, args []string) {
		store := boltdb.NewStore(&boltdb.Options{Database: storeFile})
		node := cot.NewNode(&cot.NodeOptions{
			CLIMode:       true,
			EncryptionKey: encKey,
			Store:         store,
			LogFunc:       logFunc,
		})

		if err := node.Serve(); err != nil {
			log.Fatalln(fmt.Sprintf("FATAL: %v", err))
		}

		list, err := node.ListTrustGrantTokens()
		if err != nil {
			log.Fatalln(fmt.Sprintf("FATAL: %v", err))
		}

		j, err := json.MarshalIndent(list, "", "  ")
		if err != nil {
			log.Fatalln(fmt.Sprintf("FATAL: %v", err))
		}

		log.Printf("%s\n", j)
	},
}

var registerCmd = &cobra.Command{
	Use: "register",
	Run: func(cmd *cobra.Command, args []string) {
		store := boltdb.NewStore(&boltdb.Options{Database: storeFile})
		node := cot.NewNode(&cot.NodeOptions{
			CLIMode:       true,
			EncryptionKey: encKey,
			RPCAddr:       rpcAddr,
			Store:         store,
			LogFunc:       logFunc,
		})

		if err := node.Serve(); err != nil {
			log.Fatalln(fmt.Sprintf("FATAL: %v", err))
		}

		if err := node.RequestTrust(grantorAddr, grantToken); err != nil {
			log.Fatalln(fmt.Sprintf("FATAL: %v", err))
		}
		log.Println("Registration SUCCESS!")

	},
}

var signCmd = &cobra.Command{
	Use: "sign",
	Run: func(cmd *cobra.Command, args []string) {
		store := boltdb.NewStore(&boltdb.Options{Database: storeFile})
		node := cot.NewNode(&cot.NodeOptions{
			CLIMode:       true,
			EncryptionKey: encKey,
			Store:         store,
			LogFunc:       logFunc,
		})

		if err := node.Serve(); err != nil {
			log.Fatalln(fmt.Sprintf("FATAL: %v", err))
		}

		tokenString, err := node.Sign(jwt.MapClaims{"data": signedData})
		if err != nil {
			log.Fatalln(fmt.Sprintf("FATAL: %v", err))
		}

		log.Printf("\n%s\n\n", tokenString)
	},
}

var issueCmd = &cobra.Command{
	Use: "issue",
	Run: func(cmd *cobra.Command, args []string) {
		store := boltdb.NewStore(&boltdb.Options{Database: storeFile})
		node := cot.NewNode(&cot.NodeOptions{
			CLIMode:       true,
			EncryptionKey: encKey,
			Store:         store,
			LogFunc:       logFunc,
		})

		if err := node.Serve(); err != nil {
			log.Fatalln(fmt.Sprintf("FATAL: %v", err))
		}

		token, err := node.NewGrantToken()
		if err != nil {
			log.Fatalln(fmt.Sprintf("FATAL: %v", err))
		}

		j, err := json.MarshalIndent(token, "", "  ")
		if err != nil {
			log.Fatalln(fmt.Sprintf("FATAL: %v", err))
		}

		fmt.Printf("%s\n", j)
	},
}

var trustCmd = &cobra.Command{
	Use: "trust",
	Run: func(cmd *cobra.Command, args []string) {
		log.Printf("Serving Trust on %s\n", rpcAddr)
		store := boltdb.NewStore(&boltdb.Options{Database: storeFile})
		node := cot.NewNode(&cot.NodeOptions{
			RPCAddr:       rpcAddr,
			EncryptionKey: encKey,
			Store:         store,
			LogFunc:       logFunc,
		})

		if err := node.Serve(); err != nil {
			log.Fatalln(fmt.Sprintf("FATAL: %v", err))
		}

		http.HandleFunc("/resource", func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				handleGetResource(node, w, r)
				return
			default:
				w.WriteHeader(http.StatusMethodNotAllowed)
			}
		})

		log.Printf("Starting trust server on %s - client: %t, server: %t", addr, clientMode, serverMode)
		log.Fatalln(http.ListenAndServe(addr, nil))
	},
}

func logFunc(level, message string, err error) {
	switch level {
	case cot.LogLevelError:
		log.Printf("%s: %s - %v\n", level, message, err)
	default:
		log.Printf("%s: %s\n", level, message)
	}
}

// simple server resource endpoint to test verification
func handleGetResource(node *cot.Node, w http.ResponseWriter, r *http.Request) {
	tokenString, err := cot.GetJwtFromRequest(r, "")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}

	token, err := node.Verify(tokenString)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}

	j, err := json.MarshalIndent(token, "", "  ")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}

	w.Header().Set("Content-Type", "application/json")

	if !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(j)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(j)
	return
}

func main() {
	rootCmd.PersistentFlags().StringVarP(&storeFile, "store", "f", "", "store file")
	rootCmd.PersistentFlags().StringVarP(&encKey, "encryption-key", "k", "", "encryption key")
	rootCmd.PersistentFlags().StringVarP(&addr, "addr", "a", ":3000", "address to run on")
	rootCmd.PersistentFlags().StringVarP(&rpcAddr, "rpc-addr", "r", ":3001", "address to run rpc on")

	registerCmd.PersistentFlags().StringVarP(&grantorAddr, "grantor", "g", "", "grantor address")
	registerCmd.PersistentFlags().StringVarP(&grantToken, "token", "t", "", "grant token")

	signCmd.PersistentFlags().StringVarP(&signedData, "data", "d", "", "data to sign")

	listCmd.AddCommand(listTrustCmd)
	listCmd.AddCommand(listKeyPairCmd)
	listCmd.AddCommand(listGrantTokenCmd)

	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(trustCmd)
	rootCmd.AddCommand(issueCmd)
	rootCmd.AddCommand(registerCmd)
	rootCmd.AddCommand(signCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

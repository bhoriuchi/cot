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
var rpcAddr string
var signedData string
var storeFile string
var regToken string
var regAddr string
var serverMode bool
var clientMode bool

var rootCmd = &cobra.Command{}

var registerCmd = &cobra.Command{
	Use: "register",
	Run: func(cmd *cobra.Command, args []string) {
		store := boltdb.NewStore(&boltdb.Options{Database: storeFile})
		client := cot.NewClient(&cot.ClientOptions{
			Store:   store,
			RPCAddr: rpcAddr,
			CLIMode: true,
			LogFunc: logFunc,
		})

		if err := client.Register(regAddr, regToken); err != nil {
			log.Fatalln(err)
		}
		log.Println("Registration SUCCESS!")

	},
}

var signCmd = &cobra.Command{
	Use: "sign",
	Run: func(cmd *cobra.Command, args []string) {
		store := boltdb.NewStore(&boltdb.Options{Database: storeFile})
		client := cot.NewClient(&cot.ClientOptions{
			Store:   store,
			RPCAddr: rpcAddr,
			CLIMode: true,
			LogFunc: logFunc,
		})

		tokenString, err := client.Sign(jwt.MapClaims{"data": signedData})
		if err != nil {
			log.Fatalln(err)
		}

		log.Printf("\n%s\n\n", tokenString)
	},
}

var issueCmd = &cobra.Command{
	Use: "issue",
	Run: func(cmd *cobra.Command, args []string) {
		store := boltdb.NewStore(&boltdb.Options{Database: storeFile})
		if err := store.WithLogFunc(logFunc).Init(); err != nil {
			log.Fatalln(err)
		}
		server := cot.NewServer(&cot.ServerOptions{
			Store:   store,
			LogFunc: logFunc,
		})
		token, err := server.NewRegistrationToken()
		if err != nil {
			log.Fatalln(err)
		}

		j, err := json.MarshalIndent(token, "", "  ")
		if err != nil {
			log.Fatalln(err)
		}

		fmt.Printf("%s\n", j)
	},
}

var trustCmd = &cobra.Command{
	Use: "trust",
	Run: func(cmd *cobra.Command, args []string) {
		store := boltdb.NewStore(&boltdb.Options{Database: storeFile})
		if err := store.WithLogFunc(logFunc).Init(); err != nil {
			log.Fatalln(err)
		}

		if clientMode {
			client := cot.NewClient(&cot.ClientOptions{
				RPCAddr: rpcAddr,
				Store:   store,
				LogFunc: logFunc,
			})
			if err := client.Init(); err != nil {
				log.Fatalln(err)
			}

			http.HandleFunc("/certs", func(w http.ResponseWriter, r *http.Request) {
				switch r.Method {
				case http.MethodGet:
					client.HandleGetJWKS(w, r)
					return
				default:
					w.WriteHeader(http.StatusMethodNotAllowed)
				}
			})
		}

		if serverMode {
			server := cot.NewServer(&cot.ServerOptions{
				Store:   store,
				LogFunc: logFunc,
			})
			if err := server.Init(); err != nil {
				log.Fatalln(err)
			}

			http.HandleFunc("/trust/register", func(w http.ResponseWriter, r *http.Request) {
				switch r.Method {
				case http.MethodGet:
					server.HandleIssueRegistrationToken(w, r)
					return
				case http.MethodDelete:
					server.HandleBreak(w, r)
					return
				case http.MethodPost:
					server.HandleRegister(w, r)
					return
				default:
					w.WriteHeader(http.StatusMethodNotAllowed)
				}
			})
			http.HandleFunc("/resource", func(w http.ResponseWriter, r *http.Request) {
				switch r.Method {
				case http.MethodGet:
					handleGetResource(server, w, r)
					return
				default:
					w.WriteHeader(http.StatusMethodNotAllowed)
				}
			})
		}

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
func handleGetResource(server *cot.Server, w http.ResponseWriter, r *http.Request) {
	tokenString, err := cot.GetJwtFromRequest(r, "")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}

	token, err := server.Verify(tokenString)
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
	rootCmd.PersistentFlags().StringVarP(&addr, "addr", "a", ":3000", "address to run on")
	rootCmd.PersistentFlags().StringVarP(&rpcAddr, "rpc-addr", "r", ":3001", "address to run rpc on")

	registerCmd.PersistentFlags().StringVarP(&regAddr, "url", "u", "", "registration url")
	registerCmd.PersistentFlags().StringVarP(&regToken, "token", "t", "", "registration token")

	signCmd.PersistentFlags().StringVarP(&signedData, "data", "d", "", "data to sign")

	trustCmd.PersistentFlags().BoolVarP(&serverMode, "server", "s", false, "run in server mode")
	trustCmd.PersistentFlags().BoolVarP(&clientMode, "client", "c", false, "run in client mode")

	rootCmd.AddCommand(trustCmd)
	rootCmd.AddCommand(issueCmd)
	rootCmd.AddCommand(registerCmd)
	rootCmd.AddCommand(signCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

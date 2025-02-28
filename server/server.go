package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	log.Println(w, "Hello, World!")
}

func main() {
	// Load server’s certificate and key
	cert, err := tls.LoadX509KeyPair("/certs/server.crt", "/certs/server.key")
	if err != nil {
		log.Println("Failed to load server certificate and key: ", err)
		return
	}

	// Load client CA certificate
	clientCACert, err := os.ReadFile("/certs/server.crt") // Replace with the correct CA file
	if err != nil {
		log.Println("Failed to read client CA cert: ", err)
		return
	}
	clientCertPool := x509.NewCertPool()
	clientCertPool.AppendCertsFromPEM(clientCACert)

	// Configure TLS to require and verify client certificate
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    clientCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	http.HandleFunc("/logs", func(w http.ResponseWriter, r *http.Request) {
		log.Println("Received request for /logs")
		log.Println("Hello, World!")
	})

	server := &http.Server{
		Addr:      ":443",
		Handler:   http.HandlerFunc(handler),
		TLSConfig: tlsConfig,
	}

	log.Println("Starting server on port 443...")
	err = server.ListenAndServeTLS("/certs/server.crt", "/certs/server.key")
	if err != nil {
		fmt.Println("Failed to start server: ", err)
	}
}

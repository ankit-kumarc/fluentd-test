package server

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func main(){
	serverCertPath, err := filepath.Abs("certs/server.crt")
	if err != nil {
		log.Fatalf("Error getting absolute path for server cert: %v", err)
	}

	serverKeyPath, err := filepath.Abs("certs/server.key")
	if err != nil {
		log.Fatalf("Error getting absolute path for server key: %v", err)
	}

	clientCaCert, err := os.ReadFile(serverCertPath)
	if err != nil {
		log.Fatalf("Error reading server cert: %v", err)
	}

	clientCertPool := x509.NewCertPool()
	clientCertPool.AppendCertsFromPEM(clientCaCert)

	tlsConfig := &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  clientCertPool,
		MinVersion: tls.VersionTLS12,
	}

	server := &http.Server{
		ReadHeaderTimeout: 5* time.Second,
		TLSConfig: tlsConfig,
	}

	listener, err := net.Listen("tcp", ":443")
	if err != nil {
		log.Fatalf("Error creating listener: %v", err)
	}

	err = server.ServeTLS(listener, serverCertPath, serverKeyPath)
	if err != nil {
		log.Fatalf("Error serving TLS: %v", err)
	}
}

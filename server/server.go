package main

import (
    "crypto/tls"
    "crypto/x509"
    "fmt"
    "io/ioutil"
    "net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "Hello, World!")
}

func main() {
    // Load server’s certificate and key
    cert, err := tls.LoadX509KeyPair("/certs/server.crt", "/certs/server.key")
    if err != nil {
        fmt.Println("Failed to load server certificate and key: ", err)
        return
    }

    // Load client CA certificate
    clientCACert, err := ioutil.ReadFile("/certs/server.crt") // Replace with the correct CA file
    if err != nil {
        fmt.Println("Failed to read client CA cert: ", err)
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

    server := &http.Server{
        Addr:      ":443",
        Handler:   http.HandlerFunc(handler),
        TLSConfig: tlsConfig,
    }

    fmt.Println("Starting server on port 443...")
    err = server.ListenAndServeTLS("/certs/server.crt", "/certs/server.key")
    if err != nil {
        fmt.Println("Failed to start server: ", err)
    }
}
package main

import (
	"crypto/tls"
	"encoding/base64"
	"net/http"
	"os"
)

type Message struct {
	alg   string
	jwk   string
	nonce string
	url   string
}

func main() {
	println("start")
	nonce := getNonce()

	// Quelle: https://golang.org/pkg/encoding/base64/
	input := []byte("foo\x00bar")
	encoder := base64.NewEncoder(base64.StdEncoding, os.Stdout)
	encoder.Write(input)

	// todo: prüfen was "alg" ist und ob es bleiben kann / jwk erstellen

	m := Message{"ES256", "todo", nonce, "https://localhost:14000/sign-me-up"}
	// Must close the encoder when finished to flush any partial blocks.
	// If you comment out the following line, the last partial block "r"
	// won't be encoded.
	encoder.Close()

	println("ende")
}

func getNonce() string {
	// Quelle: https://stackoverflow.com/questions/12122159/how-to-do-a-https-request-with-bad-certificate
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	// Quelle: https://stackoverflow.com/questions/38563285/how-to-execute-a-head-request-in-go
	res, err := client.Head("https://localhost:14000/nonce-plz")
	if err != nil {
		panic(err)
	}
	// Quelle: https://stackoverflow.com/questions/46021330/how-can-i-read-a-header-from-an-http-request-in-golang/46022272
	ua := res.Header.Get("Replay-Nonce")
	println("Replay-Nonce:%v", ua)
	return ua
}

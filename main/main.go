package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
)

// Quelle: https://blog.golang.org/json
type Message struct {
	alg   string
	jwk   string
	nonce string
	url   string
}

func main() {
	println("start")
	nonce := getNonce()
	combine(nonce)

	// Quelle: https://golang.org/pkg/encoding/base64/
	// todo: prüfen was "alg" ist und ob es bleiben kann / jwk erstellen
	m := Message{"ES256", "todo", nonce, "https://localhost:14000/sign-me-up"}

	b, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	encoder := base64.NewEncoder(base64.StdEncoding, os.Stdout)
	encoder.Write(b)
	encoder.Close()

	println()
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

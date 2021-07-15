package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"net/http"
)

type Message struct {
	alg   string
	jwk   string
	nonce string
	url   string
}

func main() {
	println("start")
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	order_url := newAccount(privateKey)
	_, authorization_url := newCertificate(privateKey, order_url)
	secret := authChallenge(privateKey, order_url, authorization_url)
	authChallengeAnswer(privateKey, order_url, authorization_url, secret)
}

func getNonce() string {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	res, err := client.Head("https://192.168.1.5:14000/nonce-plz")
	if err != nil {
		panic(err)
	}
	ua := res.Header.Get("Replay-Nonce")
	return ua
}

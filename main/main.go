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

	order_url := newAccount(privateKey)                                                // Create Account
	_, authorization_url, finalizeURL := newCertificate(privateKey, order_url)         // Create Order
	secret, answer_url, dns := authChallenge(privateKey, order_url, authorization_url) // Get(Request) Challenge
	authChallengeAnswer(privateKey, order_url, answer_url, secret)                     // answer Challenge
	_, _, _ = authChallenge(privateKey, order_url, authorization_url)                  // Get(Request) Overview if status is valid (not yet implemented just for visual feedback)
	makeCSRRequest(privateKey, order_url, dns, finalizeURL)                            // request a Certifikat using CSR

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

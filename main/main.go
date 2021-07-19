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

	testmode := false
	if testmode {
		//teeeest()
	} else {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}

		account_url := newAccount(privateKey)                                                // Create Account
		_, authorization_url, finalizeURL := newCertificate(privateKey, account_url)         // Create Order
		secret, answer_url, dns := authChallenge(privateKey, account_url, authorization_url) // Get(Request) Challenge
		authChallengeAnswer(privateKey, account_url, answer_url, secret)                     // answer Challenge
		_, _, _ = authChallenge(privateKey, account_url, authorization_url)                  // Get(Request) Overview if status is valid (not yet implemented just for visual feedback)
		makeCSRRequest(privateKey, account_url, dns, finalizeURL)                            // request a Certifikat using CSR
		order_url := getCertificate(privateKey, account_url)
		new_order_url := downloadCertificate(privateKey, order_url, account_url)
		certificate_url := downloadCertificate2(privateKey, new_order_url, account_url)
		downloadCertificate3(privateKey, certificate_url, authorization_url)
	}
}

func getNonce() string {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	res, err := client.Head("https://192.168.1.2:14000/nonce-plz")
	if err != nil {
		panic(err)
	}
	ua := res.Header.Get("Replay-Nonce")
	return ua
}

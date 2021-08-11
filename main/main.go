package main

import (
	"time"
)

type Message struct {
	alg   string
	jwk   string
	nonce string
	url   string
}

func main() {
	println("start")
	account_url, order_list_url := newAccount("https://192.168.1.8:14000/sign-me-up")                               // Create Account
	order_url, authorization_url, finalizeURL := newCertificate(account_url, "https://192.168.1.8:14000/order-plz") // Create Order
	secret, answer_url, dns := authChallenge(account_url, authorization_url)                                        // Get(Request) Challenge
	authChallengeAnswer(account_url, answer_url, secret)                                                            // answer Challenge
	waitForServerToUpdateStatus(account_url, authorization_url)                                                     // rest to let server update order Status
	makeCSRRequest(account_url, dns, finalizeURL)                                                                   // request a Certifikat using CSR
	certificate_url := makeCertificate(account_url, order_url)                                                      // Get(Request) extract the Certificate URL from Order
	requestCertificate(account_url, certificate_url)                                                                // Get(Request) Certifikate

	println("unused links:" + order_list_url)
}

func waitForServerToUpdateStatus(account_url string, authorization_url string) {
	valid := false
	for !valid {
		valid = checkIfStatusValid(account_url, authorization_url)
		time.Sleep(2 * time.Second)
	}
}

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
	account_url, order_list_url := newAccount("https://192.168.1.2:14000/sign-me-up")                       // Create Account
	_, authorization_url, finalizeURL := newCertificate(account_url, "https://192.168.1.2:14000/order-plz") // Create Order
	secret, answer_url, dns := authChallenge(account_url, authorization_url)                                // Get(Request) Challenge
	authChallengeAnswer(account_url, answer_url, secret)                                                    // answer Challenge
	waitForServerToUpdateStatus(account_url, authorization_url)                                             // rest to let server update order Status
	makeCSRRequest(account_url, dns, finalizeURL)                                                           // request a Certifikat using CSR
	new_order_url := downloadCertificate(account_url, order_list_url)                                       // Get(Request) the order Element
	certificate_url := downloadCertificate2(account_url, new_order_url)                                     // Get(Request) extract the Certificate URL from Order
	downloadCertificate3(account_url, certificate_url)                                                      // Get(Request) Certifikate
}

func waitForServerToUpdateStatus(account_url string, authorization_url string) {
	valid := false
	for !valid {
		valid = checkIfStatusValid(account_url, authorization_url)
		time.Sleep(2 * time.Second)
	}
}

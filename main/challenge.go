package main

import (
	"github.com/google/go-attestation/attest"
)

func getAttestAndEndorseKey() (*attest.AK, attest.EK) {
	config := &attest.OpenConfig{}
	tpm, err := attest.OpenTPM(config)
	if err != nil {
		panic(err)
	}

	eks, err := tpm.EKs()
	if err != nil {
		panic(err)
	}
	ek := eks[0]

	akConfig := &attest.AKConfig{}
	ak, err := tpm.NewAK(akConfig)
	if err != nil {
		panic(err)
	}

	return ak, ek
}

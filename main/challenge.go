package main

import (
	"github.com/google/go-attestation/attest"
)

func getAttestAndEndorseKey() attest.EK {
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
	if err != nil {
		panic(err)
	}
	akConfig := &attest.AKConfig{}
	ak, err := tpm.NewAK(akConfig)

	attestParams := ak.AttestationParameters()
	println("Hier stehen die attest Params:", string(attestParams.Public))

	akBytes, err := ak.Marshal()
	println("Hier steht akBytes:", string(akBytes))

	return ek
}

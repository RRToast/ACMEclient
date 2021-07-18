package main

import "os/exec"

/*
#!/bin/sh
cd tpm2-tss-engine/
tpm2tss-genkey -a rsa scriptKey.tss
openssl req -new -x509 -engine tpm2tss -key scriptKey.tss -keyform engine -out scriptcsr.csr
rm scriptKey.tss
mv scriptcsr.csr /home/pi
*/

func readCSRFromFile() {
	/* cmdHome := exec.Command("cd", "..")
	err := cmdHome.Run()
	if err != nil {
		println("cd .. Befehl konnte nicht ausgeführt werden", err.Error())
	}

	cmdTpm2Tss := exec.Command("cd", "tpm2-tss-engine/")
	err = cmdTpm2Tss.Run()
	if err != nil {
		println("cd tpm2-tss-engine/ Befehl konnte nicht ausgeführt werden", err.Error())
	} */

	test := exec.Command("script")
	output, err := test.Output()
	if err != nil {
		println("Error executing script :", err.Error())
	} else {
		println("output: ", string(output))
	}

	/*
		cmdGenkey := exec.Command("tpm2tss-genkey", "-a", "rsa", "scriptKey.tss")
		cmdGenkey.Dir = "/home/pi/tpm2-tss-engine/"
		err := cmdGenkey.Run()
		if err != nil {
			println("tpm2tss-genkey -a rsa scriptKey.tss Befehl konnte nicht ausgeführt werden", err.Error())
		}

		commands := []string{"openssl", "req", "-new", "-x509", "-engine", "tpm2tss", "-key", "scriptKey.tss", "-keyform", "engine", "-out", "scriptcsr.csr"}
		dir := "/home/pi/tpm2-tss-engine/"

		cmd := exec.Cmd{Args: commands, Dir: dir}
		err = cmd.Run()
		println("Run error : ", err.Error())
		value, err := cmd.Output()
		println("Output error ist :", err.Error())
		println("value :", string(value)) */

	/*
		cmdCreateCSR := exec.Command("openssl", "req", "-new", "-x509", "-engine", "tpm2tss", "-key", "scriptKey.tss", "-keyform", "engine", "-out", "scriptcsr.csr")
		cmdCreateCSR.Dir = "/home/pi/tpm2-tss-engine/"
		erre := cmdCreateCSR.Output
		erre
		if erre != nil {
			println("Output failed Terminal konnte nicht gezeigt werden", err.Error())
		} else {
			println("Output sah so aus:", string(arr))
		}

		err = cmdCreateCSR.Run()
		if err != nil {
			println("openssl req -new -x509 -engine tpm2tss -key scriptKey.tss -keyform engine -out scriptcsr.csr Befehl konnte nicht ausgeführt werden", err.Error())
		}

		cmdCleanup := exec.Command("rm", "scriptKey.tss")
		cmdCleanup.Dir = "/home/pi/tpm2-tss-engine/"
		err = cmdCleanup.Run()
		if err != nil {
			println("rm scriptKey.tss Befehl konnte nicht ausgeführt werden", err.Error())
		}

		cmdMoveFile := exec.Command("mv", "scriptcsr.csr", "/home/pi/ACMEclinet")
		cmdMoveFile.Dir = "/home/pi/tpm2-tss-engine/"
		err = cmdMoveFile.Run()
		if err != nil {
			println("mv scriptcsr.csr /home/pi Befehl konnte nicht ausgeführt werden", err.Error())
		}

		if _, err := os.Stat("scriptcsr.csr"); os.IsNotExist(err) {
			println(" scriptcsr.csr does not exist")
		} */

}

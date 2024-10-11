package main

import "os/exec"

func GenerateSBOM() {
	exec.Command("trivy")
}

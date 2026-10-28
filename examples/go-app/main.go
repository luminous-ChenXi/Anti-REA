// Example target program: simulates a closed-source commercial app with a
// license check (Go). Used to verify that anti-rea audit/harden reduces the
// signals visible to REA, before vs. after hardening.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
)

// licenseCheck is the function a reverse engineer cares about most: its symbol
// name and string constants are exactly what REA extracts first.
func licenseCheck(userKey string) bool {
	h := sha256.Sum256([]byte(userKey + "ANTI-REA-DEMO-SALT"))
	want, _ := hex.DecodeString("a1b2c3d4e5f60718293a4b5c6d7e8f90")
	return hex.EncodeToString(h[:8]) == hex.EncodeToString(want)
}

func main() {
	key := "DEMO-0000-0000"
	if len(os.Args) > 1 {
		key = os.Args[1]
	}
	fmt.Println("app ok, license =", licenseCheck(key))
}

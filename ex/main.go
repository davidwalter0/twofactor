// From the author's example
package main

import (
	"crypto"
	"fmt"
	"github.com/sec51/twofactor"
	"os"
)

func main() {
	otp, err := twofactor.NewTOTP("info@sec51.com", "Sec51", crypto.SHA1, 8)
	if err != nil {
		// return err
		fmt.Println(err)
	}
	qrBytes, err := otp.QR()
	if err != nil {
		// return err
		fmt.Println(err)
	}

	fmt.Fprint(os.Stdout, string(qrBytes))
}

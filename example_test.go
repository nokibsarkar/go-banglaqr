package banglaqr_test

import (
	"fmt"

	banglaqr "github.com/nokibsarkar/go-banglaqr"
)

// A synthetic static merchant QR (not a real merchant).
const staticQR = "00020101021126300012example.test011001234567895204481253030505802BD5913Test Merchant6005Dhaka62050501S6304A628"

func ExampleGenerate() {
	p, err := banglaqr.Generate(staticQR, banglaqr.GenerateRequest{
		Amount:               "100.50",
		Reference:            "INV-1",
		DerivationAuthorized: true, // you confirm the acquirer permits deriving dynamic QRs
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(p.Text)
	// Output: 00020101021226300012example.test011001234567895204481253030505406100.505802BD5913Test Merchant6005Dhaka62140501S0105INV-163048D64
}

func ExampleTemplate_MarshalBinary() {
	tpl, err := banglaqr.Parse(staticQR)
	if err != nil {
		fmt.Println(err)
		return
	}
	blob, _ := tpl.MarshalBinary() // store this
	back, err := banglaqr.Decode(blob)
	fmt.Println(err, back.Text() == staticQR)
	// Output: <nil> true
}

func ExampleParse_rejectsTampering() {
	_, err := banglaqr.Parse(staticQR[:len(staticQR)-1] + "0") // wrong CRC
	fmt.Println(err)
	// Output: banglaqr: CRC mismatch (offset 106)
}

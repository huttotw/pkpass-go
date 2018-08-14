package pkpass_test

import (
	"io"
	"os"
	"testing"

	"github.com/huttotw/pkpass-go"
)

func TestNew(t *testing.T) {
	cert, err := os.Open("Certificates.p12")
	if err != nil {
		t.Fatal(err)
	}
	defer cert.Close()

	r, err := pkpass.New("Coupon.pass", "", cert)
	if err != nil {
		t.Fatal(err)
	}

	f, err := os.Create("Coupon.pkpass")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	_, err = io.Copy(f, r)
}

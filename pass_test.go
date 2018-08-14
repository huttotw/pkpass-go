package pkpass_test

import (
	"io"
	"io/ioutil"
	"os"
	"testing"

	"github.com/huttotw/pkpass-go"
)

func TestNew(t *testing.T) {
	files, err := ioutil.ReadDir("Coupon.pass")
	if err != nil {
		t.Fatal(err)
	}

	cert, err := os.Open("Certificates.p12")
	if err != nil {
		t.Fatal(err)
	}
	defer cert.Close()

	r, err := pkpass.New(files, cert, "")
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

package pkpass

import (
	"archive/zip"
	"bytes"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
)

type archive struct {
	content []byte
	name    string
}

func New(files []os.FileInfo, cert io.Reader, password string) (io.Reader, error) {
	// Create a temporary directory that we will use as a scratch pad for our
	// openssl commands.
	dir, err := ioutil.TempDir("", "")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	// Copy the certificate into a file so that it can be used by
	// os.Exec
	c, err := os.Create(fmt.Sprintf("%s/certificates.p12", dir))
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_, err = io.Copy(c, cert)
	if err != nil {
		return nil, err
	}

	// Create the certificate.pem file
	err = pem(dir, password, cert)
	if err != nil {
		return nil, err
	}

	// Create the key.pem file
	err = key(dir, password, cert)
	if err != nil {
		return nil, err
	}

	// Create a new zip buffer that we will use to produce
	// the final output
	buf := new(bytes.Buffer)
	w := zip.NewWriter(buf)
	defer w.Close()

	err = bundle(w, dir, files)
	if err != nil {
		return nil, err
	}

	// Sign the manifest.json
	err = sign(w, dir, password)
	if err != nil {
		return nil, err
	}

	return buf, nil
}

func key(dir, password string, cert io.Reader) error {
	cmd := exec.Command(
		"openssl",
		"pkcs12",
		"-in",
		fmt.Sprintf("%s/certificates.p12", dir),
		"-nocerts",
		"-out",
		fmt.Sprintf("%s/key.pem", dir),
		"-passin",
		fmt.Sprintf("pass:%s", password),
		"-passout",
		fmt.Sprintf("pass:%s1234", password),
	)
	return cmd.Run()
}

func pem(dir, password string, cert io.Reader) error {
	cmd := exec.Command(
		"openssl",
		"pkcs12",
		"-in",
		fmt.Sprintf("%s/certificates.p12", dir),
		"-clcerts",
		"-nokeys",
		"-out",
		fmt.Sprintf("%s/certificate.pem", dir),
		"-passin",
		fmt.Sprintf("pass:%s", password),
	)
	return cmd.Run()
}

func bundle(w *zip.Writer, dir string, files []os.FileInfo) error {
	var m = make(map[string]string)
	for _, fi := range files {
		if fi.IsDir() {
			continue
		}

		f, err := os.Open(fmt.Sprintf("Coupon.pass/%s", fi.Name()))
		if err != nil {
			return err
		}

		b, err := ioutil.ReadAll(f)
		if err != nil {
			return err
		}

		f.Seek(0, 0)

		h := sha1.New()
		_, err = io.Copy(h, f)
		if err != nil {
			return err
		}

		sha := h.Sum(nil)
		m[fi.Name()] = fmt.Sprintf("%x", sha)

		f2, err := w.Create(fi.Name())
		if err != nil {
			return err
		}

		_, err = f2.Write(b)
		if err != nil {
			return err
		}
	}

	f, err := w.Create("manifest.json")
	if err != nil {
		return err
	}

	b, err := json.Marshal(m)
	if err != nil {
		return err
	}

	_, err = f.Write(b)
	if err != nil {
		return err
	}

	man, err := os.Create(fmt.Sprintf("%s/manifest.json", dir))
	if err != nil {
		return err
	}
	defer man.Close()

	man.Write(b)

	return nil
}

func sign(w *zip.Writer, dir string, password string) error {
	// Copy the wwdr certificate into a file so that it can be used
	// by openssl
	f, err := os.Create(fmt.Sprintf("%s/wwdr.pem", dir))
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write([]byte(wwdr))
	if err != nil {
		return err
	}

	// Sign the bundle
	cmd := exec.Command(
		"openssl",
		"smime",
		"-sign",
		"-signer",
		fmt.Sprintf("%s/certificate.pem", dir),
		"-inkey",
		fmt.Sprintf("%s/key.pem", dir),
		"-certfile",
		fmt.Sprintf("%s/wwdr.pem", dir),
		"-in",
		fmt.Sprintf("%s/manifest.json", dir),
		"-out",
		fmt.Sprintf("%s/signature", dir),
		"-outform",
		"der",
		"-binary",
		"-passin",
		fmt.Sprintf("pass:%s1234", password),
	)
	err = cmd.Run()
	if err != nil {
		return err
	}

	sig, err := os.Open(fmt.Sprintf("%s/signature", dir))
	if err != nil {
		return err
	}
	defer f.Close()

	z, err := w.Create("signature")
	if err != nil {
		return err
	}

	_, err = io.Copy(z, sig)
	if err != nil {
		return err
	}

	return nil
}

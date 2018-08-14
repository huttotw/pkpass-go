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
	"path/filepath"
)

// New will create a new Apple pass given the directory of companion files, the
// password needed to open the certificate, and the certificate. You should read
// the returned reader into a file, this file is your Apple pass and can be opened
// from iOS and macOS devices.
func New(passDir, password string, cert io.Reader) (io.Reader, error) {
	// Create a temporary directory that we will use as a scratch pad for our
	// openssl commands.
	tempDir, err := ioutil.TempDir("", "")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tempDir)

	// Copy the certificate into a file so that it can be used by
	// os.Exec
	c, err := os.Create(fmt.Sprintf("%s/certificates.p12", tempDir))
	if err != nil {
		return nil, err
	}
	defer c.Close()

	_, err = io.Copy(c, cert)
	if err != nil {
		return nil, err
	}

	// Create the certificate.pem file
	err = pem(tempDir, password, cert)
	if err != nil {
		return nil, err
	}

	// Create the key.pem file
	err = key(tempDir, password, cert)
	if err != nil {
		return nil, err
	}

	// Create a new zip buffer that we will use to produce
	// the final output
	buf := new(bytes.Buffer)
	w := zip.NewWriter(buf)
	defer w.Close()

	// Create the bundle of files, this will include everything
	// in the directory
	err = bundle(w, passDir, tempDir)
	if err != nil {
		return nil, err
	}

	// Sign the manifest.json
	err = sign(w, tempDir, password)
	if err != nil {
		return nil, err
	}

	return buf, nil
}

// key will generate the private key that is needed in the openssl smime command
func key(tempDir, password string, cert io.Reader) error {
	cmd := exec.Command(
		"openssl",
		"pkcs12",
		"-in",
		fmt.Sprintf("%s/certificates.p12", tempDir),
		"-nocerts",
		"-out",
		fmt.Sprintf("%s/key.pem", tempDir),
		"-passin",
		fmt.Sprintf("pass:%s", password),
		"-passout",
		fmt.Sprintf("pass:%s1234", password),
	)
	return cmd.Run()
}

// key will generate the certificate's pem file that is needed in the openssl smime command
func pem(tempDir, password string, cert io.Reader) error {
	cmd := exec.Command(
		"openssl",
		"pkcs12",
		"-in",
		fmt.Sprintf("%s/certificates.p12", tempDir),
		"-clcerts",
		"-nokeys",
		"-out",
		fmt.Sprintf("%s/certificate.pem", tempDir),
		"-passin",
		fmt.Sprintf("pass:%s", password),
	)
	return cmd.Run()
}

// bundle will read all of the files in the passDir, create a manifest.json, and
// add all files to the zip archive.
func bundle(w *zip.Writer, passDir, tempDir string) error {
	files, err := ioutil.ReadDir(passDir)
	if err != nil {
		return err
	}

	var m = make(map[string]string)
	for _, fi := range files {
		// Skip directories, they are meaningless in this situation
		if fi.IsDir() {
			continue
		}

		// Open the file in the directory
		f, err := os.Open(filepath.Join(passDir, fi.Name()))
		if err != nil {
			return err
		}

		// Create the sha writer
		hw := sha1.New()

		// Create the zip writer
		zw, err := w.Create(fi.Name())
		if err != nil {
			return err
		}

		mw := io.MultiWriter(hw, zw)

		// Write the file to the zip writer
		_, err = io.Copy(mw, f)
		if err != nil {
			return err
		}

		// Add the hash to a map, later we will json.Marshal this to make manifest.json
		sha := hw.Sum(nil)
		m[fi.Name()] = fmt.Sprintf("%x", sha)
	}

	// Create the file writer
	f, err := os.Create(filepath.Join(tempDir, "manifest.json"))
	if err != nil {
		return err
	}
	defer f.Close()

	// Create the zip writer
	zw, err := w.Create("manifest.json")
	if err != nil {
		return err
	}

	mw := io.MultiWriter(f, zw)

	// Write the JSON to the file, and zip
	err = json.NewEncoder(mw).Encode(m)
	if err != nil {
		return err
	}

	return nil
}

// sign will sign the manifest json using the keys and certificates created
// in key and pem respectively. It will then write the signature file to the zip
// archive so that we can open the pass.
func sign(w *zip.Writer, tempDir, password string) error {
	// Copy the wwdr certificate into a file so that it can be used
	// by openssl
	f, err := os.Create(fmt.Sprintf("%s/wwdr.pem", tempDir))
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
		fmt.Sprintf("%s/certificate.pem", tempDir),
		"-inkey",
		fmt.Sprintf("%s/key.pem", tempDir),
		"-certfile",
		fmt.Sprintf("%s/wwdr.pem", tempDir),
		"-in",
		fmt.Sprintf("%s/manifest.json", tempDir),
		"-out",
		fmt.Sprintf("%s/signature", tempDir),
		"-outform",
		"der",
		"-binary",
		"-passin",
		fmt.Sprintf("pass:%s1234", password),
	)
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		return err
	}

	sig, err := os.Open(fmt.Sprintf("%s/signature", tempDir))
	if err != nil {
		return err
	}
	defer f.Close()

	zw, err := w.Create("signature")
	if err != nil {
		return err
	}

	_, err = io.Copy(zw, sig)
	if err != nil {
		return err
	}

	return nil
}

package encrypt

import (
	"bytes"
	"strings"
	"testing"
)

const strongPassword1 string = "correct horse battery staple"
const strongPassword2 string = "correct horse battery staple 2"

var sharedSalt Salt

func getSharedSalt(t *testing.T) Salt {
	if sharedSalt == nil {
		var e error
		sharedSalt, e = GenerateSalt()
		if e != nil {
			t.Errorf("Unexpected error generating salt: %v", e)
		}
	}
	return sharedSalt
}

func TestEncryptContent(t *testing.T) {
	content := "My secret content!"

	e, err := NewEncrypter(strongPassword1, getSharedSalt(t))
	if err != nil {
		t.Errorf("Error creating the Encrypter: %v", err)
	}

	encrypted, err := e.Encrypt([]byte(content))
	if err != nil {
		t.Errorf("Error encrypting content: %v", err)
	}

	d := NewDecrypter(strongPassword1)
	content2Bytes, err := d.Decrypt([]byte(encrypted))
	if err != nil {
		t.Errorf("Error decrypting content: %v", err)
	}

	content2 := string(content2Bytes)
	if content != content2 {
		t.Errorf("Expected content '%s' after decryption, but got '%s' instead.", content, content2)
	}
}

func TestBadPassword(t *testing.T) {
	content := "My secret content!"
	e, _ := NewEncrypter(strongPassword1, getSharedSalt(t))
	encrypted, err := e.Encrypt([]byte(content))
	if err != nil {
		t.Errorf("Error encrypting content: %v", err)
	}

	d := NewDecrypter(strongPassword2)
	_, err = d.Decrypt([]byte(encrypted))
	if err == nil {
		t.Errorf("Expected an error decrypting content with the wrong password")
	}
	if !strings.Contains(err.Error(), "bad password") {
		t.Errorf("Expected a bad password error. Got '%v'", err)
	}
}

func TestTampering(t *testing.T) {
	content := "My secret content!"

	e, _ := NewEncrypter(strongPassword1, getSharedSalt(t))

	encrypted, err := e.Encrypt([]byte(content))
	if err != nil {
		t.Errorf("Error encrypting content: %v", err)
	}

	//Change content value
	encrypted[len(encrypted)/2] = encrypted[len(encrypted)/2] - 1

	d := NewDecrypter(strongPassword1)
	_, err = d.Decrypt([]byte(encrypted))
	if err == nil {
		t.Errorf("Expected an error decrypting tampered content")
	}
	if !strings.Contains(err.Error(), "tampered") {
		t.Errorf("Expected a tampering detected error. Got '%v'", err)
	}
}

func TestSameInputDifferentOutput(t *testing.T) {
	content := "My secret content!"

	e1, err := NewEncrypter(strongPassword1, getSharedSalt(t))
	if err != nil {
		t.Errorf("Error creating the 1st Encrypter: %v", err)
	}

	salt2, _ := GenerateSalt()
	e2, err := NewEncrypter(strongPassword1, salt2)
	if err != nil {
		t.Errorf("Error creating the 2nd Encrypter: %v", err)
	}

	ciphertext1, err := e1.Encrypt([]byte(content))
	if err != nil {
		t.Errorf("Error encrypting with the 1nd Encrypter: %v", err)
	}

	ciphertext2, err := e2.Encrypt([]byte(content))
	if err != nil {
		t.Errorf("Error encrypting with the 2nd Encrypter: %v", err)
	}

	if bytes.Compare(ciphertext1, ciphertext2) == 0 {
		t.Error("Different salts are expected to generate different content, even with the same password")
	}
}

func TestVersionCheck(t *testing.T) {
	// Increment the version count to simulate a newer version of the file.
	// This is not as clean as I'd like, but it's simple.
	oldVersion := version
	version = version + 1

	content := "My secret content!"
	e, _ := NewEncrypter(strongPassword1, getSharedSalt(t))
	encrypted, err := e.Encrypt([]byte(content))
	if err != nil {
		t.Errorf("Error encrypting content: %v", err)
	}

	// Restore the original version value
	version = oldVersion

	d := NewDecrypter(strongPassword1)
	_, err = d.Decrypt([]byte(encrypted))
	if err == nil {
		t.Errorf("Expected an error decrypting content with a higher version")
	}
	if !strings.Contains(err.Error(), "version") {
		t.Errorf("Expected a version error. Got '%v'", err)
	}

}

func TestCloseDecrypt(t *testing.T) {
	e, _ := NewEncrypter(strongPassword1, getSharedSalt(t))
	ciphertext, _ := e.Encrypt([]byte("Encrypted content"))
	d := NewDecrypter(strongPassword1)
	d.Decrypt(ciphertext)

	d.Close()
	for i := range d.password {
		if d.password[i] != 0 {
			t.Errorf("Expected password to have been cleared from memory. Got %v", d.password)
		}
	}

	if len(d.ciphers) != 0 {
		t.Errorf("Expected AES keys to have been cleared from memory.")
	}
}

func BenchmarkGenerateSalt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateSalt()
	}
}

func BenchmarkNewEncrypter(b *testing.B) {
	salt, _ := GenerateSalt()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewEncrypter(strongPassword1, salt)
	}
}

func BenchmarkEncrypt(b *testing.B) {
	content := []byte("1234567890123456789012345678901234567890123456789012345678901234")
	salt, _ := GenerateSalt()
	e, _ := NewEncrypter(strongPassword1, salt)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Encrypt(content)
	}
}

func BenchmarkNewDecrypter(b *testing.B) {

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewDecrypter(strongPassword1)
	}
}

func BenchmarkDecryptFirstTime(b *testing.B) {
	content := []byte("1234567890123456789012345678901234567890123456789012345678901234")
	salt, _ := GenerateSalt()
	e, _ := NewEncrypter(strongPassword1, salt)
	ciphertext, _ := e.Encrypt(content)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d := NewDecrypter(strongPassword1)
		d.Decrypt(ciphertext) // The first call is expected to be very expensive as it's where the key is calculated.
	}
}

func BenchmarkDecrypt(b *testing.B) {
	content := []byte("1234567890123456789012345678901234567890123456789012345678901234")
	salt, _ := GenerateSalt()
	e, _ := NewEncrypter(strongPassword1, salt)
	ciphertext, _ := e.Encrypt(content)

	d := NewDecrypter(strongPassword1)
	d.Decrypt(ciphertext) // The first call is expected to be very expensive as it's where the key is calculated.

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.Decrypt(ciphertext) // Subsequent calls should be fast.
	}
}

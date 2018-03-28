package encrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"log"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/xts"
)

// 512 bits salt matches what VeraCrypt uses with PBKDF2 to prevent rainbow table attacks.
// NIST recomments at least 32 bits (4 bytes).
const saltLen = 64

const argon2Time = 20
const argon2Memory = 64 * 1024
const argon2Threads = 4

// VeraCrypt uses 50,000 itr. NIST recommends at least 10,000 itr.
const pbkdf2ItrCount = 50000

var pbkdf2Hash = sha512.New // SHA-512 matches VeraCrypt.
const pbkdf2KeyLen = aesKeyLen * 4

// AES-256 key used in XTS mode.
// 256 bits is a requirement of AES-256. To use XTS mode, we double it From the XTS documentation: "The key must be
// twice the length of the underlying cipher's key."
const aesKeyLen = 32 * 2
const xtsSectorNum = 0

const sha512DigestLen = 64

var magicBytes = []byte{'G', 'O', 'O', 'D', 'P', 'W'} // To validate password choice.
var version byte = 1

// Salt is an encryption salt available through Encrypter or Decrypter objects.
type Salt []byte

// GenerateSalt will generate a random salt suitable to be used by Encrypter and Decrypter.
//
// A Decrypter will require the same salt as the Encrypter to be able to read its content.
//
// Security Notes
//
// (1) Don't use the same salt *between* users. If they end up having the same password, this will be easily noticeable
// by an attacker.
//
// (2) Its safe to share the salt publicly, as long as the password is kept a secret.
func GenerateSalt() (Salt, error) {
	b := make([]byte, saltLen)
	l, e := rand.Read(b)
	if e != nil {
		return nil, e
	}
	if l != saltLen {
		return nil, fmt.Errorf("wrong salt length generated. Expected %d, got %d", saltLen, l)
	}

	return Salt(b), nil
}

// IsValid true if the salt value is valid.
func (s *Salt) IsValid() bool {
	return len(*s) == saltLen
}

// Len returns the length of the salt
func (s *Salt) Len() int {
	return saltLen
}

// Encrypter will encrypt plain content to be secure against unauthorized access and against tampering.
//
// Use a Decrypter object to decrypt it.
type Encrypter struct {
	salt   Salt
	cipher *xts.Cipher
}

// NewEncrypter returns a new encrypter using password and salt.
func NewEncrypter(password []byte, salt Salt) (*Encrypter, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("NewEncrypter cannot have empty password")
	}

	if !salt.IsValid() {
		return nil, fmt.Errorf("invalid salt: use GenerateSalt() to create one")
	}

	// Generate the AES encryption key from the password and salt
	aesKey, e := aesKeyFromPasswordAndSalt(password, salt)
	if e != nil {
		return nil, e
	}
	defer func(aesKey []byte) {
		for i := range aesKey {
			aesKey[i] = 0
		}
	}(aesKey)

	cipher, e := xts.NewCipher(aes.NewCipher, aesKey)
	if e != nil {
		return nil, e
	}

	return &Encrypter{salt, cipher}, nil
}

// Close will disable the Encrypter and erase the password from memory.
// It can be used to limit the lifetime of the password in memory. While you're already in trouble if an attacker
// already has access to memory, this adds a little defense in depth and could make the attack more difficult in some
// scenarios.
func (ec *Encrypter) Close() {}

// Encrypt will encrypt plaintext and return the result.
func (ec *Encrypter) Encrypt(plaintext []byte) ([]byte, error) {
	if plaintext == nil {
		return nil, fmt.Errorf("invalid plaintext: nil")
	}

	// Create a SHA-512 digest on the plain content to detect data tampering
	digest := sha512.Sum512(plaintext)
	if len(digest) != sha512DigestLen {
		return nil, fmt.Errorf("unexpected SHA512 hash length. Expected %d, got %d", sha512DigestLen, len(digest))
	}

	// 1 byte space to store version
	// 1 byte space to store padding len once we have it
	lenContentToEncrypt := len(magicBytes) + 1 + 1 + len(digest) + len(plaintext)

	// As a block cipher, the content's length must be a multiple of the AES block size (16 bytes).
	// To achieve this, we add padding to the plain content so that its size matches.
	paddingLen := 0
	extra := lenContentToEncrypt % aes.BlockSize
	if extra != 0 {
		paddingLen = aes.BlockSize - extra
	}
	lenContentToEncrypt += paddingLen

	// Copy the plain text content to the buffer
	contentLen := ec.salt.Len() + lenContentToEncrypt
	content := make([]byte, contentLen)
	i := 0
	i += copy(content[i:], ec.salt)
	i += copy(content[i:], magicBytes)
	content[i] = byte(version)
	i++
	content[i] = byte(paddingLen)
	i++
	i += copy(content[i:], make([]byte, paddingLen))
	i += copy(content[i:], digest[:])
	i += copy(content[i:], plaintext)
	if i != contentLen {
		log.Panicf("Unexpected encryption error: expected length of copied plain content to be %d, got %d\n", contentLen, i)
	}

	// Encrypt supports in-place encryption.
	// Note that we don't encrypt the salt as we need it for decrypting.
	ec.cipher.Encrypt(content[ec.salt.Len():], content[ec.salt.Len():], xtsSectorNum)

	return content, nil
}

// Decrypter will decrypt content encrypted by an Encrypter object that has the same password.
//
// Note that the salt is stored as part of the encrypted content format so we don't need it upon decryption.
type Decrypter struct {
	password []byte
	// List of scrypt salt to the associated AES-key.
	ciphers map[[saltLen]byte]*xts.Cipher
}

// NewDecrypter returns a new decrypter using password
func NewDecrypter(password []byte) (*Decrypter, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("NewDecrypter cannot have empty password")
	}

	return &Decrypter{password, make(map[[saltLen]byte]*xts.Cipher)}, nil
}

// Close will disable the Decrypter and erase the password from memory.
// It can be used to limit the lifetime of the password in memory. While you're already in trouble if an attacker
// already has access to memory, this adds a little defense in depth and could make the attack more difficult in some
// scenarios.
func (d *Decrypter) Close() {
	for i := range d.password {
		d.password[i] = 0
	}

	for k := range d.ciphers {
		delete(d.ciphers, k)
	}
}

// Decrypt will decrypt ciphertext and return the result.
func (d *Decrypter) Decrypt(ciphertext []byte) ([]byte, error) {
	if ciphertext == nil {
		return nil, fmt.Errorf("invalid ciphertext: nil")
	}

	var salt [saltLen]byte
	copy(salt[:], ciphertext[:saltLen])

	// Check our cache to see if we have already calculated the AES key
	// as it's expensive.
	cipher, ok := d.ciphers[salt]
	if !ok {
		aesKey, e := aesKeyFromPasswordAndSalt(d.password, salt[:])
		if e != nil {
			return nil, e
		}
		defer func(aesKey []byte) {
			for i := range aesKey {
				aesKey[i] = 0
			}
		}(aesKey)

		cipher, e = xts.NewCipher(aes.NewCipher, aesKey)
		if e != nil {
			return nil, e
		}
		d.ciphers[salt] = cipher
	}

	ciphertext = ciphertext[saltLen:]

	plaintext := make([]byte, len(ciphertext))
	cipher.Decrypt(plaintext, ciphertext, xtsSectorNum)
	i := 0

	// Check magic bytes
	if bytes.Compare(plaintext[i:i+len(magicBytes)], magicBytes) != 0 {
		return nil, fmt.Errorf("bad password")
	}
	i += len(magicBytes)

	// Check version
	if plaintext[i] > version {
		return nil, fmt.Errorf("unsupported version: we are version '%d' and the content is version '%d'", version, plaintext[i])
	}
	i++

	// Jump over padding
	paddingLen := plaintext[i]
	i += 1 + int(paddingLen)

	storedDigest := plaintext[i : i+sha512DigestLen]
	i += sha512DigestLen

	plaintext = plaintext[i:]

	realDigest := sha512.Sum512(plaintext)
	if bytes.Compare(storedDigest, realDigest[:]) != 0 {
		return nil, fmt.Errorf("message authentication code mismatch: data is corrupted and may have been tampered with")
	}

	return plaintext, nil
}

// aesKeyFromPasswordAndSalt will create the AES key using password hashing.
func aesKeyFromPasswordAndSalt(password []byte, salt []byte) ([]byte, error) {

	// We apply PBKDF2 and Argon2 one after the other, using the same salt for both.
	pbkdf2Key := pbkdf2.Key(password, salt, pbkdf2ItrCount, pbkdf2KeyLen, pbkdf2Hash)
	aesKey := argon2.IDKey(pbkdf2Key, salt, argon2Time, argon2Memory, argon2Threads, aesKeyLen)

	return aesKey, nil
}

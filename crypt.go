package gockham

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"hash"

	"golang.org/x/crypto/pbkdf2"
)

// Crypt contains serveral cryptographic utilities
type Crypt struct {
	md5Hash    hash.Hash // MD5 hash (highly insecure!)
	sha1Hash   hash.Hash // SHA1 hash (moderately insecure!)
	sha256Hash hash.Hash // SHA256 hash (fairly secure)
	//	aesEncrypt cipher.BlockMode
	//	aesDecrypt cipher.BlockMode
}

// NewCrypt creates a Crypt
func newCrypt() (Crypt, error) {
	/*
		aes, err := aes.NewCipher(key)
		if err != nil {
			return Crypt{}, err
		}
	*/
	return Crypt{
		md5Hash:    md5.New(),
		sha1Hash:   sha1.New(),
		sha256Hash: sha256.New(),
		//		aesEncrypt: cipher.NewCBCEncrypter(aes, key),
		//		aesDecrypt: cipher.NewCBCDecrypter(aes, key),
	}, nil
}

// Encode64 encodes a BASE64 string
func Encode64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// Decode64 decodes a BASE64 string
func Decode64(encoded string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(encoded)
}

// EncodeURL64 encodes a BASE64 string using URL encoding
func EncodeURL64(url string) string {
	return base64.URLEncoding.EncodeToString([]byte(url))
}

// DecodeURL64 decodes a BASE64 string using URL encoding
func DecodeURL64(encoded string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(encoded)
}

// Md5 returns a MD5 hash of given data. This is very insecure these days!
func (c Crypt) Md5(data []byte) []byte {
	c.md5Hash.Reset()
	c.md5Hash.Write(data)
	return c.md5Hash.Sum(nil)
}

// Sha1 returns the SHA1 hash of given data. This is moderately insecure.
func (c Crypt) Sha1(data []byte) []byte {
	c.sha1Hash.Reset()
	c.sha1Hash.Write(data)
	return c.sha1Hash.Sum(nil)
}

// Sha1ToString returns a BASE64 encoded SHA1 hash of given data. This is moderately insecure.
func (c Crypt) Sha1ToString(data string) string {
	return Encode64(c.Sha1([]byte(data)))
}

// Sha256 returns the SHA256 hash of given data. This is moderately insecure.
func (c Crypt) Sha256(data []byte) []byte {
	c.sha256Hash.Reset()
	c.sha256Hash.Write(data)
	return c.sha256Hash.Sum(nil)
}

// Sha256ToString returns a BASE64 encoded SHA256 hash of given data. This is moderately insecure.
func (c Crypt) Sha256ToString(data string) string {
	return Encode64(c.Sha256([]byte(data)))
}

// PKCS5Padding implements a PKCS#5 padding on an array of bytes
// and returns a padded array of bytes
func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

// PKCS5Trimming trims a PKCS#5 padded array of bytes and returns
// the unpadded array of bytes.
func PKCS5Trimming(encrypt []byte) ([]byte, error) {
	padding := int(encrypt[len(encrypt)-1])
	if padding > len(encrypt) {
		return nil, errors.New("Bad PKCS5 trimming")
	}
	return encrypt[:len(encrypt)-padding], nil
}

// GenerateRandomBytes generates an array of random bytes
func (c Crypt) GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

// PBKDF2 hashes a password using the key derivation function PBKDF2 as
// defined in RFC 2898 / PKCS #5 v2.0
func (c Crypt) PBKDF2(saltSize int, password []byte) []byte {
	salt, _ := c.GenerateRandomBytes(saltSize)
	return c.PBKDF2Hash(salt, password)
}

func (c Crypt) PBKDF2Hash(salt []byte, password []byte) []byte {
	hash := make([]byte, len(salt))
	copy(hash, salt)
	hash = append(hash, pbkdf2.Key(password, salt, 4096, sha256.Size, sha256.New)...)
	return hash
}

// PBKDF2ToString hashes a password using the key derivation function PBKDF2
// Password if salted so salt size is needed in order to regenerate the hash
// password and returned value are BASE64 encoded
func (c Crypt) PBKDF2ToString(saltSize int, password string) string {
	return Encode64(c.PBKDF2(saltSize, []byte(password)))
}

// PBKDF2Compare checks if the given password matches the BASE64 salted hash
func (c Crypt) PBKDF2Compare(saltSize int, password string, hash string) bool {
	hashBin, _ := Decode64(hash)
	salt := hashBin[:saltSize]
	check := c.PBKDF2Hash(salt, []byte(password))
	return bytes.Equal(hashBin, check)
}

/*
func (c Crypt) AesEncrypt(data []byte) []byte {
	data = PKCS5Padding(data, c.aesEncrypt.BlockSize())
	c.aesEncrypt.CryptBlocks(data, data)
	return data
}

func (c Crypt) AesDecrypt(data []byte) []byte {
	c.aesDecrypt.CryptBlocks(data, data)
	return PKCS5Trimming(data)
}

func (c Crypt) CipherUrl(uri string) string {
	ciphered := c.AesEncrypt([]byte(uri))
	return "/~" + EncodeUrl64(string(ciphered))
}
*/

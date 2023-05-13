package kdf

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"hash"
	"strings"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
)

// THashFunc - supported hash functions for pkbdf2
type THashFunc uint8

const (
	SHA256 THashFunc = iota + 1
	SHA512
	SHA3256
	SHA3384
	SHA3512
)

const typPBKDF2 = "pbkdf2"

// KDFPBKDF2 - structure for pkbdf2 key derivation function
type KDFPBKDF2 struct {
	ConfigPBKDF2
	h []byte
}

// ConfigPBKDF2 - configuration details for pbkdf2
type ConfigPBKDF2 struct {
	Iterations int
	SaltLength uint32
	KeyLength  int
	HashFunc   THashFunc
	hFunc      func() hash.Hash
	Salt       []byte
}

// NewKDFPBKDF2 - creates a new instance of PBKDF2 using the given configuration parameters
func NewKDFPBKDF2(cfg ConfigPBKDF2) (p *KDFPBKDF2) {

	kdfP := KDFPBKDF2{ConfigPBKDF2: cfg}

	// check for config values or set with default sane values

	if kdfP.Iterations == 0 {
		kdfP.Iterations = 300000
	}

	if kdfP.SaltLength == 0 {
		kdfP.SaltLength = 16
	}

	if kdfP.KeyLength == 0 {
		kdfP.KeyLength = 32
	}

	if kdfP.HashFunc.String() == "unknown" {
		kdfP.HashFunc = SHA3384
	}

	switch kdfP.HashFunc {
	case SHA256:
		kdfP.hFunc = sha256.New
	case SHA512:
		kdfP.hFunc = sha512.New
	case SHA3256:
		kdfP.hFunc = sha3.New256
	case SHA3384:
		kdfP.hFunc = sha3.New384
	case SHA3512:
		kdfP.hFunc = sha3.New512
	}

	return &kdfP
}

// ParsePBKDF2 - parses an pbkdf2 output format and generates a KDF with the configuration
func ParsePBKDF2(inputStr string) (p *KDFPBKDF2, err error) {

	i := strings.Split(inputStr, "$")

	if len(i) != 5 {
		return nil, fmt.Errorf("parsepbkdf2: invalid encoded format")
	}

	p = new(KDFPBKDF2)

	var hashFunc string
	_, err = fmt.Sscanf(i[2], "t=%d,s=%s", &p.Iterations, &hashFunc)
	if err != nil {
		return nil, fmt.Errorf("parseargon2id: %w", err)
	}

	p.HashFunc = newTHashFunc(hashFunc)
	switch p.HashFunc {
	case SHA256:
		p.hFunc = sha256.New
	case SHA512:
		p.hFunc = sha512.New
	case SHA3256:
		p.hFunc = sha3.New256
	case SHA3384:
		p.hFunc = sha3.New384
	case SHA3512:
		p.hFunc = sha3.New512
	}

	p.Salt, err = base64.RawStdEncoding.Strict().DecodeString(i[3])
	if err != nil {
		return nil, fmt.Errorf("parseargon2id: %w", err)
	}
	p.SaltLength = uint32(len(p.Salt))

	p.h, err = base64.RawStdEncoding.Strict().DecodeString(i[4])
	if err != nil {
		return nil, fmt.Errorf("parseargon2id: %w", err)
	}
	p.KeyLength = len(p.h)

	return
}

// SetSalt - sets a custom salt
func (p *KDFPBKDF2) SetSalt(salt []byte) {
	p.Salt = salt
}

// Generate - generates a input from the input
func (p *KDFPBKDF2) Generate(input []byte) {
	// if no salt is set, we generate a new one here
	if len(p.Salt) == 0 {
		p.Salt = make([]byte, p.SaltLength)
		rand.Read(p.Salt)
	}

	p.h = pbkdf2.Key(input, p.Salt, p.Iterations, p.KeyLength, p.hFunc)
}

// Verify - verifies a given input with what is stored
func (p *KDFPBKDF2) Verify(input []byte) (ok bool) {
	h := pbkdf2.Key(input, p.Salt, p.Iterations, p.KeyLength, p.hFunc)
	return (subtle.ConstantTimeCompare(p.h, h) == 1)
}

// Key - returns the computed hash
func (p *KDFPBKDF2) Key() (key []byte) {
	return p.h
}

// String - returns an encoded representation of the derived key with the parameters used
func (p *KDFPBKDF2) String() (str string) {
	return fmt.Sprintf("$%s$t=%d,s=%s$%s$%s", typPBKDF2, p.Iterations, p.HashFunc, base64.RawStdEncoding.EncodeToString(p.Salt), base64.RawStdEncoding.EncodeToString(p.h))
}

func (t THashFunc) String() (str string) {

	tTYpes := []string{"unknown", "sha-256", "sha-512", "sha3-256", "sha3-384", "sha3-512"}
	tInt := int(t)

	if tInt > len(tTYpes) {
		tInt = 0 // if no known hash func is given
	}

	return tTYpes[tInt]
}

// newTHashFunc - returns instance of hash function unsed
func newTHashFunc(hashStr string) (t THashFunc) {

	tTYpes := []string{"unknown", "sha-256", "sha-512", "sha3-256", "sha3-384", "sha3-512"}

	t = THashFunc(0) // default is unknown

	for index, typ := range tTYpes {
		if typ == hashStr {
			return THashFunc(index)
		}
	}

	return
}

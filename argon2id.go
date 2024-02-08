package kdf

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const typArgon = "argon2id"

// KDFArgon2ID - structure for argon2id key derivation function
type KDFArgon2ID struct {
	*ConfigArgon2ID
	h []byte
}

// ConfigArgon2ID - configuration details for argon2id
type ConfigArgon2ID struct {
	Type        Type
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
	Salt        []byte
}

// DefaultConfigArgon2ID - returns default configuration for Argon2ID
func DefaultConfigArgon2ID() (kdfA *ConfigArgon2ID) {
	kdfA = new(ConfigArgon2ID)

	kdfA.Type = ARGON2ID
	kdfA.Memory = 64 * 1024
	kdfA.Iterations = 3
	kdfA.Parallelism = 4
	kdfA.SaltLength = 16
	kdfA.KeyLength = 32

	return kdfA
}

func (aCfg *ConfigArgon2ID) Instance() (cfg any) {
	return
}

// NewKDFArgon2ID - creates a new instance of Argon2ID using the given configuration parameters
func NewKDFArgon2ID(cfg *ConfigArgon2ID) (a *KDFArgon2ID) {

	kdfA := KDFArgon2ID{ConfigArgon2ID: cfg}

	// check for config values or set with default sane values
	if kdfA.Memory == 0 {
		kdfA.Memory = 64 * 1024
	}

	if kdfA.Iterations == 0 {
		kdfA.Iterations = 3
	}

	if kdfA.Parallelism == 0 {
		kdfA.Parallelism = 4
	}

	if kdfA.SaltLength == 0 {
		kdfA.SaltLength = 16
	}

	if kdfA.KeyLength == 0 {
		kdfA.KeyLength = 32
	}

	return &kdfA
}

// ParseArgon2ID - parses an argon2id output format and generates a KDF with the configuration
func ParseArgon2ID(inputStr string) (a *KDFArgon2ID, err error) {

	i := strings.Split(inputStr, "$")

	if len(i) != 6 {
		return nil, fmt.Errorf("parseargon2id: invalid encoded format")
	}

	var version int
	_, err = fmt.Sscanf(i[2], "v=%d", &version)
	if err != nil {
		return nil, fmt.Errorf("parseargon2id: %w", err)
	}

	if version != argon2.Version {
		return nil, fmt.Errorf("parseargon2id: incompatible version %d", version)
	}

	a = new(KDFArgon2ID)
	a.ConfigArgon2ID = new(ConfigArgon2ID)

	_, err = fmt.Sscanf(i[3], "m=%d,t=%d,p=%d", &a.Memory, &a.Iterations, &a.Parallelism)
	if err != nil {
		return nil, fmt.Errorf("parseargon2id: %w", err)
	}

	a.Salt, err = base64.RawStdEncoding.Strict().DecodeString(i[4])
	if err != nil {
		return nil, fmt.Errorf("parseargon2id: %w", err)
	}
	a.SaltLength = uint32(len(a.Salt))

	a.h, err = base64.RawStdEncoding.Strict().DecodeString(i[5])
	if err != nil {
		return nil, fmt.Errorf("parseargon2id: %w", err)
	}
	a.KeyLength = uint32(len(a.h))

	return
}

// SetSalt - sets a custom salt
func (a *KDFArgon2ID) SetSalt(salt []byte) {
	a.Salt = salt
}

// Generate - generates a input from the input
func (a *KDFArgon2ID) Generate(input []byte) {
	// if no salt is set, we generate a new one here
	if len(a.Salt) == 0 {
		a.Salt = make([]byte, a.SaltLength)
		rand.Read(a.Salt)
	}

	a.h = argon2.IDKey([]byte(input), a.Salt, a.Iterations, a.Memory, a.Parallelism, a.KeyLength)
}

// Verify - verifies a given input with what is stored
func (a *KDFArgon2ID) Verify(input []byte) (ok bool) {
	h := argon2.IDKey([]byte(input), a.Salt, a.Iterations, a.Memory, a.Parallelism, a.KeyLength)
	return (subtle.ConstantTimeCompare(a.h, h) == 1)
}

// Key - returns the computed hash
func (a *KDFArgon2ID) Key() (key []byte) {
	return a.h
}

// String - returns an encoded representation of the derived key with the parameters used
func (a *KDFArgon2ID) String() (str string) {
	return fmt.Sprintf("$%s$v=%d$m=%d,t=%d,p=%d$%s$%s", typArgon, argon2.Version, a.Memory, a.Iterations, a.Parallelism, base64.RawStdEncoding.EncodeToString(a.Salt), base64.RawStdEncoding.EncodeToString(a.h))
}

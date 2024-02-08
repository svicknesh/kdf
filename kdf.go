package kdf

import (
	"fmt"
	"strings"
)

// Type - custom type for KDF
type Type uint8

const (
	// PBKDF2 - password based key derivation function
	PBKDF2 Type = iota + 1

	// ARGON2ID - uses argon2id
	ARGON2ID
)

// KDF - interface for different implementations of key derivation functions
type KDF interface {
	SetSalt(salt []byte)
	Generate(input []byte)
	Verify(input []byte) (ok bool)
	Key() (key []byte)
	String() (str string)
}

func New[T *ConfigArgon2ID | *ConfigPBKDF2](cfg T) (k KDF, err error) {

	switch cfgType := any(cfg).(type) {
	case *ConfigArgon2ID:
		return NewKDFArgon2ID(cfgType), nil
	case *ConfigPBKDF2:
		return NewKDFPBKDF2(cfgType), nil
	default:
		err = fmt.Errorf("new: unknown kdf type given")
	}

	return
}

// Parse - parses an encoded string and returns an instance of KDF
func Parse(inputStr string) (kdf KDF, err error) {

	if strings.HasPrefix(inputStr, "$argon2id$") {
		return ParseArgon2ID(inputStr)
	} else if strings.HasPrefix(inputStr, "$pbkdf2$") {
		return ParsePBKDF2(inputStr)
	}

	return nil, fmt.Errorf("parse: unknown format") // if we reach here, the format is unknown
}

// String - returns name of KDF
func (t Type) String() (str string) {

	tStr := []string{"unknown", "pbkdf2", "argon2id"}
	tInt := int(t)

	if tInt > len(tStr) {
		tInt = 0 // if an unknown Type is given, we default to 0
	}

	return tStr[tInt]
}

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
	Generate(input []byte)
	Verify(input []byte) (ok bool)
	Key() (hash []byte)
	String() (str string)
}

// Config - structure for configuring kdf
type Config struct {
	ConfigPBKDF2   ConfigPBKDF2
	ConfigArgon2ID ConfigArgon2ID
}

func New(t Type, cfg Config) (k KDF, err error) {

	switch t {
	case PBKDF2:
		return NewKDFPBKDF2(cfg.ConfigPBKDF2), nil
	case ARGON2ID:
		return NewKDFArgon2ID(cfg.ConfigArgon2ID), nil
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

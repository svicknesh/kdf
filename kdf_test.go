package kdf_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/svicknesh/kdf"
)

func TestArgon2IDDefault(t *testing.T) {

	k, err := kdf.New(kdf.DefaultConfigArgon2ID())
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	//k.SetSalt([]byte("what a wonderful world"))

	k.Generate([]byte("hello, world!"))
	fmt.Println(k)

	k1, err := kdf.Parse(k.String())
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(k1)
	fmt.Println(k1.Key())
	fmt.Println(k1.Verify([]byte("hello, world!")))

	/*
		for some  use cases, we don't need to store the string,
		just the calculated hash from Key(), which makes it harder for
		people to guess what is being done.

		For these kinds of scenarios, create the config using custom parameters
		and run the Verify() function manually.

		BitWarden does something similar to this.
	*/

}

func TestArgon2IDCustom(t *testing.T) {

	k, err := kdf.New(&kdf.ConfigArgon2ID{
		Memory:      128 * 1024,
		Iterations:  10,
		Parallelism: 5,
		SaltLength:  16,
		KeyLength:   32,
	})

	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	k.Generate([]byte("hello, world!"))
	fmt.Println(k)

	k1, err := kdf.Parse(k.String())
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(k1)
	fmt.Println(k1.Verify([]byte("hello, world!")))

}

func TestPBKDF2Default(t *testing.T) {

	k, err := kdf.New(kdf.DefaultConfigPBKDF2())
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	k.Generate([]byte("hello, world!"))
	fmt.Println(k)

	k1, err := kdf.Parse(k.String())
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(k1)
	//fmt.Println(k1.Key())
	fmt.Println(k1.Verify([]byte("hello, world!")))

}

func TestPBKDF2Custom(t *testing.T) {

	k, err := kdf.New(&kdf.ConfigPBKDF2{
		Iterations: 1000000,
		SaltLength: 16,
		KeyLength:  32,
	})

	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	k.Generate([]byte("hello, world!"))
	fmt.Println(k)

	k1, err := kdf.Parse(k.String())
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(k1)
	fmt.Println(k1.Verify([]byte("hello, world!")))

}

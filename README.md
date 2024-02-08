# Golang Key Derivation Function (KDF) Library

## Using `argon2id` KDF

```go
// create a new instance of Argon2ID using default parameters
k, err := kdf.New(kdf.DefaultConfigArgon2ID())
if nil != err {
    fmt.Println(err)
    os.Exit(1)
}

// the `k.SetSalt()` function lets the user set the desired salt to be used by `k,Generate`, instead of generating random bytes

// generate key from given input
k.Generate([]byte("hello, world!"))
fmt.Println(k) // outputs hash and all the parameters in encoded format

h:= k.Key() // returns the derived key 
fmt.Println(h)

// parses an encoded string for verification
k1, err := kdf.Parse(k.String())
if nil != err {
    fmt.Println(err)
    os.Exit(1)
}
fmt.Println(k1)
fmt.Println(k1.Verify([]byte("hello, world!"))) // verifies the given input matches what was stored

/*
    for some  use cases, we don't need to store the string,
    just the calculated hash from Key(), which makes it harder for
    people to guess what is being done.

    For these kinds of scenarios, create the config using custom parameters
    and run the Verify() function manually.

    BitWarden does something similar to this.
*/

```

### Customizing `argon2id` parameters

```go
kdf.ConfigArgon2ID {
    Memory:      128 * 1024,
    Iterations:  10,
    Parallelism: 5,
    SaltLength:  16,
    KeyLength:   32,
}
```

```go
k, err := kdf.New(&kdf.ConfigArgon2ID{
    Memory:      128 * 1024,
    Iterations:  10,
    Parallelism: 5,
    SaltLength:  16,
    KeyLength:   32,
})

// the rest of the usage is the same as above

```


## Using `pkbdf2` KDF

```go
// create a new instance of pkbdf2 using default parameters
k, err := kdf.New(kdf.DefaultConfigPBKDF2())
if nil != err {
    fmt.Println(err)
    os.Exit(1)
}

// the `k.SetSalt()` function lets the user set the desired salt to be used by `k,Generate`, instead of generating random bytes

// generate key from given input
k.Generate([]byte("hello, world!"))
fmt.Println(k) // outputs hash and all the parameters in encoded format

h:= k.Key() // returns the derived key 
fmt.Println(h)

// parses an encoded string for verification
k1, err := kdf.Parse(k.String())
if nil != err {
    fmt.Println(err)
    os.Exit(1)
}
fmt.Println(k1)
fmt.Println(k1.Verify([]byte("hello, world!"))) // verifies the given input matches what was stored
```

### Customizing `pkbdf2` parameters

```go
kdf.ConfigPBKDF2 {
    Iterations:  1000000,
    SaltLength:  16,
    KeyLength:   32,
}
```

```go
k, err := kdf.New(&kdf.ConfigPBKDF2{
    Iterations: 1000000,
    SaltLength: 16,
    KeyLength:  32,
})

// the rest of the usage is the same as above

```

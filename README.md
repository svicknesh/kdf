# Golang Key Derivation Function (KDF) Helper Library

## Using `argon2id` KDF

```go
// create a new instance of Argon2ID using default parameters
k, err := kdf.New(kdf.ARGON2ID, kdf.Config{})
if nil != err {
    fmt.Println(err)
    os.Exit(1)
}

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

### Customizing `argon2id` parameters

```go
kdf.Config{
    ConfigArgon2ID: kdf.ConfigArgon2ID{
        Memory:      128 * 1024,
        Iterations:  10,
        Parallelism: 5,
        SaltLength:  16,
        KeyLength:   32,
    }
}
```

```go
k, err := kdf.New(kdf.ARGON2ID, kdf.Config{ConfigArgon2ID: kdf.ConfigArgon2ID{
    Memory:      128 * 1024,
    Iterations:  10,
    Parallelism: 5,
    SaltLength:  16,
    KeyLength:   32,
}})
```


## Using `pkbdf2` KDF

```go
// create a new instance of pkbdf2 using default parameters
k, err := kdf.New(kdf.PBKDF2, kdf.Config{})
if nil != err {
    fmt.Println(err)
    os.Exit(1)
}

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
kdf.Config{
    ConfigPBKDF2: kdf.ConfigPBKDF2{
        Iterations:  1000000,
        SaltLength:  16,
        KeyLength:   32,
    }
}
```

```go
k, err := kdf.New(kdf.PBKDF2, kdf.Config{ConfigPBKDF2: kdf.ConfigPBKDF2{
    Iterations: 1000000,
    SaltLength: 16,
    KeyLength:  32,
}})
```

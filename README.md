![pwd package](https://user-images.githubusercontent.com/58651329/144160290-996de8ec-3a13-48fe-9474-99cac1367aa8.png)

# Installation
```go
go get -u github.com/itrepablik/pwd
```

# Argon2
[Argon2](https://en.wikipedia.org/wiki/Argon2) is a key derivation function that was selected as the winner of the Password Hashing Competition in July 2015. It was designed by Alex Biryukov, Daniel Dinu, and Dmitry Khovratovich from the University of Luxembourg. It was originally written in C in this repo at [phc-winner-argon2
](https://github.com/P-H-C/phc-winner-argon2). It has a built-in Go's library at https://pkg.go.dev/golang.org/x/crypto/argon2.

# Usage
This is how you can use the simplified argon2id in your next Go project.
```go
package main

import (
	"github.com/itrepablik/pwd"
)

func main() {
	// Method 1: To initialize the pwd with custom configs, use the SetArgon2Configs() method
	var pwdConf = &pwd.Argon2Configs{
		Memory:      128 * 1024,
		Iterations:  1,
		Parallelism: 4,
		SaltLength:  16,
		KeyLength:   32,
	}
	pwdConf.SetArgon2Configs(pwdConf)

	// Generate Argon2id secured hash password
	argon2Hash, err := pwdConf.HashAndSalt("yourPlainPassword")
	if err != nil {
		errInfo := fmt.Sprintf("error hashing password: %s", err.Error())
		log.Fatal(errInfo)
		return
	}
	fmt.Println("argon2Hash: ", argon2Hash)

	// Validate Argon2id secured hash password
	isPwdCorrect, err := pwdConf.CheckPasswordHash("yourPlainPassword", argon2Hash)
	if err != nil {
		errInfo := fmt.Sprintf("error checking password: %s", err.Error())
		log.Fatal(errInfo)
		return
	}
	fmt.Println("Password is correct:", isPwdCorrect)

	// Method 2: To initialize the pwd with default configs, use the NewArgon2id() method
	var pwd = pwd.NewArgon2id()

	// Generate Argon2id secured hash password
	argon2Hash1, err := pwd.HashAndSalt("yourPlainPassword")
	if err != nil {
		errInfo := fmt.Sprintf("error hashing password: %s", err.Error())
		log.Fatal(errInfo)
		return
	}
	fmt.Println("argon2Hash1: ", argon2Hash1)

	// Validate Argon2id secured hash password
	isPwdCorrect1, err := pwd.CheckPasswordHash("yourPlainPassword", argon2Hash1)
	if err != nil {
		errInfo := fmt.Sprintf("error checking password: %s", err.Error())
		log.Fatal(errInfo)
		return
	}
	fmt.Println("Password is correct:", isPwdCorrect1)
}
```

# Subscribe to Maharlikans Code Youtube Channel:
Please consider subscribing to my Youtube Channel to recognize my work on any of my tutorial series. Thank you so much for your support!
https://www.youtube.com/c/MaharlikansCode?sub_confirmation=1

# License
Code is distributed under MIT license, feel free to use it in your proprietary projects as well.

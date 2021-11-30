![ITRLog](https://user-images.githubusercontent.com/58651329/80480060-96624d80-8982-11ea-994f-153f4f987fbe.png)

The simplified usage of [Zap](https://github.com/uber-go/zap) and [Lumberjack](https://github.com/natefinch/lumberjack) logging systems in Go for easier usage of the library.

# Installation
```
go get -u github.com/itrepablik/pwd
```

# Argon2
[Argon2](https://en.wikipedia.org/wiki/Argon2) is a key derivation function that was selected as the winner of the Password Hashing Competition in July 2015. It was designed by Alex Biryukov, Daniel Dinu, and Dmitry Khovratovich from the University of Luxembourg. It was originally written in C in this repo at [phc-winner-argon2
](https://github.com/P-H-C/phc-winner-argon2). It has a built-in Go's library at https://pkg.go.dev/golang.org/x/crypto/argon2.

# Usage
This is how you can use the simplified argon2id in your next Go project.
```
package main

import (
	"github.com/itrepablik/pwd"
)

func init() {
	// Customize the Argon2id settings
	pwd.SetArgon2Configs(128*1024, 1, 2, 32, 32)
}

func main() {
	errInfo := ""

	// Generate Argon2id secured hash password
	argon2Hash, err := pwd.HashAndSalt("yourPlainPassword")
	if err != nil {
		errInfo = fmt.Sprintf("error hashing password: %s", err.Error())
		log.Fatal(errInfo)
		return
	}
	fmt.Println("argon2Hash: ", argon2Hash)

	// Validate Argon2id secured hash password
	isPwdCorrect, err := pwd.CheckPasswordHash("yourPlainPassword", argon2Hash)
	if err != nil {
		errInfo := fmt.Sprintf("error checking password: %s", err.Error())
		log.Fatal(errInfo)
		return
	}
	fmt.Println("Password is correct:", isPwdCorrect)
}
```

# Subscribe to Maharlikans Code Youtube Channel:
Please consider subscribing to my Youtube Channel to recognize my work on any of my tutorial series. Thank you so much for your support!
https://www.youtube.com/c/MaharlikansCode?sub_confirmation=1

# License
Code is distributed under MIT license, feel free to use it in your proprietary projects as well.

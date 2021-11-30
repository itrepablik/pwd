package pwd

import "testing"

func TestSetArgon2Configs(t *testing.T) {
	SetArgon2Configs(64*1024, 1, 2, 16, 32)
	if agc.Memory != 64*1024 {
		t.Errorf("Memory should be 64*1024, but %d", agc.Memory)
	}

	if agc.Iterations != 1 {
		t.Errorf("Iterations should be 1, but %d", agc.Iterations)
	}

	if agc.Parallelism != 2 {
		t.Errorf("Parallelism should be 2, but %d", agc.Parallelism)
	}

	if agc.SaltLength != 16 {
		t.Errorf("SaltLength should be 16, but %d", agc.SaltLength)
	}

	if agc.KeyLength != 32 {
		t.Errorf("KeyLength should be 32, but %d", agc.KeyLength)
	}
}

func TestHashAndSalt(t *testing.T) {
	SetArgon2Configs(64*1024, 1, 2, 16, 32)
	pwd := "password"

	argon2Hash, err := HashAndSalt(pwd)
	if err != nil {
		t.Errorf("error hashing password: %s", err.Error())
	}

	if argon2Hash == "" {
		t.Errorf("hash should not be empty")
	}

	t.Logf("argon2Hash: %s", argon2Hash)
}

func TestCheckPasswordHash(t *testing.T) {
	SetArgon2Configs(64*1024, 1, 2, 16, 32)
	pwd := "password"

	argon2Hash, err := HashAndSalt(pwd)
	if err != nil {
		t.Errorf("error hashing password: %s", err.Error())
	}

	if argon2Hash == "" {
		t.Errorf("hash should not be empty")
	}

	t.Logf("argon2Hash: %s", argon2Hash)

	if ok, err := CheckPasswordHash("password", argon2Hash); err != nil {
		t.Errorf("error checking password: %s", err.Error())
	} else if !ok {
		t.Errorf("incorrect password")
	} else {
		t.Logf("password is correct")
	}
}

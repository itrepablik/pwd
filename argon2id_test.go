package pwd

import "testing"

func TestSetArgon2Configs(t *testing.T) {
	// To customize the pwd Argon2id configs, use the SetArgon2Configs() method
	var pwd = &Argon2Configs{
		Memory:      128 * 1024,
		Iterations:  1,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}
	pwd.SetArgon2Configs(pwd)

	if pwd.Memory != 128*1024 {
		t.Errorf("Expected pwd.Memory to be 128*1024, got %d", pwd.Memory)
	}

	if pwd.Iterations != 1 {
		t.Errorf("Expected pwd.Iterations to be 1, got %d", pwd.Iterations)
	}

	if pwd.Parallelism != 2 {
		t.Errorf("Expected pwd.Parallelism to be 2, got %d", pwd.Parallelism)
	}

	if pwd.SaltLength != 16 {
		t.Errorf("Expected pwd.SaltLength to be 16, got %d", pwd.SaltLength)
	}

	if pwd.KeyLength != 32 {
		t.Errorf("Expected pwd.KeyLength to be 32, got %d", pwd.KeyLength)
	}
}

func TestHashAndSalt(t *testing.T) {
	// To customize the pwd Argon2id configs, use the SetArgon2Configs() method
	var pwd = &Argon2Configs{
		Memory:      128 * 1024,
		Iterations:  1,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}
	pwd.SetArgon2Configs(pwd)

	argon2Hash, err := pwd.HashAndSalt("password")
	if err != nil {
		t.Errorf("Expected err to be nil, got %v", err)
	}

	if len(argon2Hash) != 98 {
		t.Errorf("Expected len(argon2Hash) to be 98, got %d", len(argon2Hash))
	}

	t.Logf("argon2Hash: %s", argon2Hash)
}

func TestCheckPasswordHash(t *testing.T) {
	// To customize the pwd Argon2id configs, use the SetArgon2Configs() method
	var pwd = &Argon2Configs{
		Memory:      128 * 1024,
		Iterations:  1,
		Parallelism: 4,
		SaltLength:  16,
		KeyLength:   32,
	}
	pwd.SetArgon2Configs(pwd)

	argon2Hash, err := pwd.HashAndSalt("password")
	if err != nil {
		t.Errorf("Expected err to be nil, got %v", err)
	}

	if len(argon2Hash) != 98 {
		t.Errorf("Expected len(argon2Hash) to be 98, got %d", len(argon2Hash))
	}

	t.Logf("argon2Hash: %s", argon2Hash)

	if ok, err := pwd.CheckPasswordHash("password", argon2Hash); err != nil {
		t.Errorf("Expected err to be nil, got %v", err)
	} else if !ok {
		t.Errorf("Incorrect password")
	} else {
		t.Logf("Password is correct")
	}
}

package main

import "testing"

func TestPasswordHashing(t *testing.T) {
	password := "secret123"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}
	if hash == password {
		t.Fatalf("hash should not equal the original password")
	}
	if !CheckPasswordHash(password, hash) {
		t.Fatalf("CheckPasswordHash should return true for correct password")
	}
}

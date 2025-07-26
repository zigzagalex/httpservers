package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestHashAndCheckPassword(t *testing.T) {
	password := "gosecret123"

	// Step 1: Hash the password
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("unexpected error hashing password: %v", err)
	}

	if hash == password {
		t.Fatal("hash should not be the same as password")
	}

	// Step 2: Check that password matches hash
	err = CheckPasswordHash(password, hash)
	if err != nil {
		t.Errorf("expected password to match hash, but got error: %v", err)
	}

	// Step 3: Check that wrong password fails
	wrong := "not-the-password"
	err = CheckPasswordHash(wrong, hash)
	if err == nil {
		t.Error("expected error for wrong password, got nil")
	}
}

func TestJWT_CreateAndValidate(t *testing.T) {
	secret := "supersecret"
	userID := uuid.New()
	expiresIn := time.Hour

	token, err := MakeJWT(userID, secret, expiresIn)
	if err != nil {
		t.Fatalf("MakeJWT failed: %v", err)
	}
	if token == "" {
		t.Fatal("Expected token, got empty string")
	}

	parsedID, err := ValidateJWT(token, secret)
	if err != nil {
		t.Fatalf("ValidateJWT failed: %v", err)
	}
	if parsedID != userID {
		t.Fatalf("Expected user ID %v, got %v", userID, parsedID)
	}
}

func TestJWT_ExpiredToken(t *testing.T) {
	secret := "supersecret"
	userID := uuid.New()

	token, err := MakeJWT(userID, secret, -1*time.Hour) // Expired already
	if err != nil {
		t.Fatalf("MakeJWT failed: %v", err)
	}

	parsedID, err := ValidateJWT(token, secret)
	if err == nil {
		t.Fatal("Expected error due to expired token, got none")
	}
	if parsedID != uuid.Nil {
		t.Fatalf("Expected Nil UUID, got %v", parsedID)
	}
}

func TestJWT_WrongSecret(t *testing.T) {
	secret := "supersecret"
	badSecret := "notsupersecret"
	userID := uuid.New()

	token, err := MakeJWT(userID, secret, time.Hour)
	if err != nil {
		t.Fatalf("MakeJWT failed: %v", err)
	}

	parsedID, err := ValidateJWT(token, badSecret)
	if err == nil {
		t.Fatal("Expected error due to wrong secret, got none")
	}
	if parsedID != uuid.Nil {
		t.Fatalf("Expected Nil UUID, got %v", parsedID)
	}
}

package crypto

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestAESEncryptDecrypt(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	plaintext := []byte("Hello, World! This is a test message.")

	ciphertext, err := AESEncrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	if bytes.Equal(plaintext, ciphertext) {
		t.Error("Ciphertext should not equal plaintext")
	}

	decrypted, err := AESDecrypt(ciphertext, key)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted text does not match original: got %s, want %s", decrypted, plaintext)
	}
}

func TestAESEncryptDecryptBase64(t *testing.T) {
	key := DeriveKey("my-secret-password")
	plaintext := []byte("Secret data to encrypt")

	ciphertextB64, err := AESEncryptBase64(plaintext, key)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	decrypted, err := AESDecryptBase64(ciphertextB64, key)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted text does not match original")
	}
}

func TestAESInvalidKey(t *testing.T) {
	shortKey := []byte("too-short")
	plaintext := []byte("test")

	_, err := AESEncrypt(plaintext, shortKey)
	if err != ErrInvalidKey {
		t.Errorf("Expected ErrInvalidKey, got: %v", err)
	}
}

func TestDeriveKey(t *testing.T) {
	key1 := DeriveKey("password1")
	key2 := DeriveKey("password1")
	key3 := DeriveKey("password2")

	if !bytes.Equal(key1, key2) {
		t.Error("Same password should derive same key")
	}

	if bytes.Equal(key1, key3) {
		t.Error("Different passwords should derive different keys")
	}

	if len(key1) != 32 {
		t.Errorf("Key should be 32 bytes, got %d", len(key1))
	}
}

func TestGenerateKey(t *testing.T) {
	key1, err := GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	key2, err := GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	if len(key1) != 32 {
		t.Errorf("Key should be 32 bytes, got %d", len(key1))
	}

	if bytes.Equal(key1, key2) {
		t.Error("Generated keys should be unique")
	}
}

func TestRSAKeyPair(t *testing.T) {
	key, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	if key.N.BitLen() != 2048 {
		t.Errorf("Key should be 2048 bits, got %d", key.N.BitLen())
	}
}

func TestRSASaveLoadKey(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test_key.pem")

	key, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	err = SavePrivateKey(key, keyPath)
	if err != nil {
		t.Fatalf("Failed to save private key: %v", err)
	}

	// Check file permissions
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("Failed to stat key file: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("Key file should have 0600 permissions, got %o", info.Mode().Perm())
	}

	loadedKey, err := LoadPrivateKey(keyPath)
	if err != nil {
		t.Fatalf("Failed to load private key: %v", err)
	}

	if !key.Equal(loadedKey) {
		t.Error("Loaded key does not match original")
	}
}

func TestRSAPublicKeyPEM(t *testing.T) {
	key, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	pem, err := GetPublicKeyPEM(key)
	if err != nil {
		t.Fatalf("Failed to get public key PEM: %v", err)
	}

	parsedPub, err := ParsePublicKey(pem)
	if err != nil {
		t.Fatalf("Failed to parse public key: %v", err)
	}

	if !key.PublicKey.Equal(parsedPub) {
		t.Error("Parsed public key does not match original")
	}
}

func TestRSASignVerify(t *testing.T) {
	key, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	data := []byte("Data to sign")

	signature, err := Sign(data, key)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	err = Verify(data, signature, &key.PublicKey)
	if err != nil {
		t.Errorf("Signature verification failed: %v", err)
	}

	// Modify data and verify fails
	modifiedData := []byte("Modified data")
	err = Verify(modifiedData, signature, &key.PublicKey)
	if err != ErrInvalidSignature {
		t.Error("Verification should fail for modified data")
	}
}

func TestRSASignVerifyBase64(t *testing.T) {
	key, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	data := []byte("Data to sign in base64")

	signatureB64, err := SignBase64(data, key)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	err = VerifyBase64(data, signatureB64, &key.PublicKey)
	if err != nil {
		t.Errorf("Signature verification failed: %v", err)
	}
}

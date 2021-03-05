// SPDX-FileCopyrightText: 2021 Alvar Penning
//
// SPDX-License-Identifier: GPL-3.0-or-later

package doubleratchet

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

func TestDh(t *testing.T) {
	alicePub, alicePriv, err := dhKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	bobPub, bobPriv, err := dhKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	aliceSec, err := dh(alicePriv, bobPub)
	if err != nil {
		t.Fatal(err)
	}

	bobSec, err := dh(bobPriv, alicePub)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(aliceSec, bobSec) {
		t.Fatalf("Alice's and Bob's secret differ, %v %v", aliceSec, bobSec)
	}
}

func TestChainKdfInput(t *testing.T) {
	testcases := []struct {
		input   []byte
		isError bool
	}{
		{nil, true},
		{[]byte{0x01}, true},
		{[]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20}, false},
	}

	for _, testcase := range testcases {
		_, _, err := chainKdf(testcase.input)
		if (err != nil) != testcase.isError {
			t.Errorf("%v resulted in err %v", testcase.input, err)
		}
	}
}

func TestChainKdfOutput(t *testing.T) {
	ckIn := make([]byte, 32)
	if _, err := rand.Read(ckIn); err != nil {
		t.Fatal(err)
	}

	ckOut, msgKey, err := chainKdf(ckIn)
	if err != nil {
		t.Fatal(err)
	} else if len(ckOut) != 32 || len(msgKey) != 32 {
		t.Fatalf("invalid output length, %v %v", ckOut, msgKey)
	}
}

func TestRootKdfInput(t *testing.T) {
	testcases := []struct {
		input   []byte
		isError bool
	}{
		{nil, true},
		{[]byte{0x01}, true},
		{[]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20}, false},
	}

	for _, testcase := range testcases {
		_, _, err := rootKdf(testcase.input, []byte{0x00})
		if (err != nil) != testcase.isError {
			t.Errorf("%v resulted in err %v", testcase.input, err)
		}
	}
}

func TestRootKdfOutput(t *testing.T) {
	rkIn := make([]byte, 32)
	dh := make([]byte, 32)
	if _, err := rand.Read(rkIn); err != nil {
		t.Fatal(err)
	} else if _, err := rand.Read(dh); err != nil {
		t.Fatal(err)
	}

	rkOut, ck, err := rootKdf(rkIn, dh)
	if err != nil {
		t.Fatal(err)
	} else if len(rkOut) != 32 || len(ck) != 32 {
		t.Fatalf("invalid output length, %v %v", rkOut, ck)
	}
}

func TestEncryptionDecryption(t *testing.T) {
	msgKey := make([]byte, 32)
	associatedData := make([]byte, 32)
	if _, err := rand.Read(msgKey); err != nil {
		t.Fatal(err)
	} else if _, err := rand.Read(associatedData); err != nil {
		t.Fatal(err)
	}

	plaintextIn := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit.")

	ciphertext, err := encrypt(msgKey, plaintextIn, associatedData)
	if err != nil {
		t.Fatal(err)
	}

	plaintextOut, err := decrypt(msgKey, ciphertext, associatedData)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plaintextIn, plaintextOut) {
		t.Fatalf("plaintext differs, %v %v", plaintextIn, plaintextOut)
	}
}

func TestEncryptionDecryptionKeyOutOfSync(t *testing.T) {
	msgKey := make([]byte, 32)
	associatedData := make([]byte, 32)
	if _, err := rand.Read(msgKey); err != nil {
		t.Fatal(err)
	} else if _, err := rand.Read(associatedData); err != nil {
		t.Fatal(err)
	}

	plaintextIn := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit.")

	ciphertext, err := encrypt(msgKey, plaintextIn, associatedData)
	if err != nil {
		t.Fatal(err)
	}

	// The other peer's ratchet is out of sync.
	if _, err := rand.Read(msgKey); err != nil {
		t.Fatal(err)
	}

	plaintextOut, err := decrypt(msgKey, ciphertext, associatedData)
	if err != nil {
		return
	}

	if bytes.Equal(plaintextIn, plaintextOut) {
		t.Fatal("AEAD decryption worked successfully")
	}
}

func TestEncryptionDecryptionAdOutOfSync(t *testing.T) {
	msgKey := make([]byte, 32)
	associatedData := make([]byte, 32)
	if _, err := rand.Read(msgKey); err != nil {
		t.Fatal(err)
	} else if _, err := rand.Read(associatedData); err != nil {
		t.Fatal(err)
	}

	plaintextIn := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit.")

	ciphertext, err := encrypt(msgKey, plaintextIn, associatedData)
	if err != nil {
		t.Fatal(err)
	}

	// The other peer uses other associated data.
	if _, err := rand.Read(associatedData); err != nil {
		t.Fatal(err)
	}

	plaintextOut, err := decrypt(msgKey, ciphertext, associatedData)
	if err != nil {
		return
	}

	if bytes.Equal(plaintextIn, plaintextOut) {
		t.Fatal("AEAD decryption worked successfully")
	}
}

func TestEncryptionDecryptionJitterCipher(t *testing.T) {
	msgKey := make([]byte, 32)
	associatedData := make([]byte, 32)
	if _, err := rand.Read(msgKey); err != nil {
		t.Fatal(err)
	} else if _, err := rand.Read(associatedData); err != nil {
		t.Fatal(err)
	}

	plaintextIn := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit.")

	ciphertext, err := encrypt(msgKey, plaintextIn, associatedData)
	if err != nil {
		t.Fatal(err)
	}

	// Something went wrong within the ciphertext part.
	for i := 0; i < len(ciphertext)-sha256.Size; i++ {
		ciphertext[i] ^= 0xff
	}

	plaintextOut, err := decrypt(msgKey, ciphertext, associatedData)
	if err != nil {
		return
	}

	if !bytes.Equal(plaintextIn, plaintextOut) {
		t.Fatal("AEAD decryption worked successfully")
	}
}

func TestEncryptionDecryptionJitterHmac(t *testing.T) {
	msgKey := make([]byte, 32)
	associatedData := make([]byte, 32)
	if _, err := rand.Read(msgKey); err != nil {
		t.Fatal(err)
	} else if _, err := rand.Read(associatedData); err != nil {
		t.Fatal(err)
	}

	plaintextIn := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit.")

	ciphertext, err := encrypt(msgKey, plaintextIn, associatedData)
	if err != nil {
		t.Fatal(err)
	}

	// Something went wrong within the HMAC part.
	for i := len(ciphertext) - sha256.Size; i < len(ciphertext); i++ {
		ciphertext[i] ^= 0xff
	}

	plaintextOut, err := decrypt(msgKey, ciphertext, associatedData)
	if err != nil {
		return
	}

	if !bytes.Equal(plaintextIn, plaintextOut) {
		t.Fatal("AEAD decryption worked successfully")
	}
}

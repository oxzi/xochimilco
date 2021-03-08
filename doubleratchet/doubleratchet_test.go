// SPDX-FileCopyrightText: 2021 Alvar Penning
//
// SPDX-License-Identifier: GPL-3.0-or-later

package doubleratchet

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestDoubelRatchetPingPong(t *testing.T) {
	sessKey := make([]byte, 32)
	if _, err := rand.Read(sessKey); err != nil {
		t.Fatal(err)
	}

	associatedData := []byte("AD")

	bobPub, bobPriv, err := dhKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	alice, err := CreateActive(sessKey, associatedData, bobPub)
	if err != nil {
		t.Fatal(err)
	}

	bob, err := CreatePassive(sessKey, associatedData, bobPub, bobPriv)
	if err != nil {
		t.Fatal(err)
	}

	at1 := []byte("hello bob")
	ah1, ac1, err := alice.Encrypt(at1)
	if err != nil {
		t.Fatal(err)
	}

	bat1, err := bob.Decrypt(ah1, ac1)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(at1, bat1) {
		t.Fatalf("plaintext differ, %s %s", at1, bat1)
	}

	bt1 := []byte("hello alice")
	bh1, bc1, err := bob.Encrypt(bt1)
	if err != nil {
		t.Fatal(err)
	}

	abt1, err := alice.Decrypt(bh1, bc1)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(bt1, abt1) {
		t.Fatalf("plaintext differ, %s %s", bt1, abt1)
	}

	bt2 := []byte("another message from bob")
	bh2, bc2, err := bob.Encrypt(bt2)
	if err != nil {
		t.Fatal(err)
	}

	abt2, err := alice.Decrypt(bh2, bc2)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(bt2, abt2) {
		t.Fatalf("plaintext differ, %s %s", bt2, abt2)
	}
}

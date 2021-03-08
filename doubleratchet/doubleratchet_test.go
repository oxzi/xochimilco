// SPDX-FileCopyrightText: 2021 Alvar Penning
//
// SPDX-License-Identifier: GPL-3.0-or-later

package doubleratchet

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestDoubleRatchetPingPong(t *testing.T) {
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

	actions := []struct {
		sender   *DoubleRatchet
		receiver *DoubleRatchet
		msgs     int
	}{
		{alice, bob, 1},
		{bob, alice, 1},
		{alice, bob, 2},
		{bob, alice, 3},
		{alice, bob, 5},
		{bob, alice, 8},
		{alice, bob, 13},
		{bob, alice, 21},
	}

	for _, action := range actions {
		for i := 0; i < action.msgs; i++ {
			msgIn := make([]byte, 16)
			if _, err := rand.Read(msgIn); err != nil {
				t.Fatal(err)
			}

			header, ciphertext, err := action.sender.Encrypt(msgIn)
			if err != nil {
				t.Fatal(err)
			}

			msgOut, err := action.receiver.Decrypt(header, ciphertext)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(msgIn, msgOut) {
				t.Fatalf("plaintext differ, %x %x", msgIn, msgOut)
			}
		}
	}
}

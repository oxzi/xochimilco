// SPDX-FileCopyrightText: 2021 Alvar Penning
//
// SPDX-License-Identifier: GPL-3.0-or-later

package doubleratchet

import (
	"bytes"
	"crypto/rand"
	norand "math/rand"
	"testing"
)

func testDoubleRatchetSetup(t *testing.T) (alice, bob *DoubleRatchet) {
	sessKey := make([]byte, 32)
	if _, err := rand.Read(sessKey); err != nil {
		t.Fatal(err)
	}

	associatedData := []byte("AD")

	bobPub, bobPriv, err := dhKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	alice, err = CreateActive(sessKey, associatedData, bobPub)
	if err != nil {
		t.Fatal(err)
	}

	bob, err = CreatePassive(sessKey, associatedData, bobPub, bobPriv)
	if err != nil {
		t.Fatal(err)
	}

	return
}

func TestDoubleRatchetPingPong(t *testing.T) {
	alice, bob := testDoubleRatchetSetup(t)
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

			ciphertext, err := action.sender.Encrypt(msgIn)
			if err != nil {
				t.Fatal(err)
			}

			msgOut, err := action.receiver.Decrypt(ciphertext)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(msgIn, msgOut) {
				t.Fatalf("plaintext differ, %x %x", msgIn, msgOut)
			}
		}
	}
}

func TestDoubleRatchetLoss(t *testing.T) {
	alice, bob := testDoubleRatchetSetup(t)
	actions := []struct {
		sender   *DoubleRatchet
		receiver *DoubleRatchet
		msgs     int
		losses   int
	}{
		{alice, bob, 1, 0},
		{bob, alice, 1, 1},
		{alice, bob, 2, 1},
		{bob, alice, 3, 2},
		{alice, bob, 5, 3},
		{bob, alice, 7, 5},
	}

	for _, action := range actions {
		for i := 0; i < action.msgs; i++ {
			msgIn := make([]byte, 16)
			if _, err := rand.Read(msgIn); err != nil {
				t.Fatal(err)
			}

			ciphertext, err := action.sender.Encrypt(msgIn)
			if err != nil {
				t.Fatal(err)
			}

			if i < action.losses {
				continue
			}

			msgOut, err := action.receiver.Decrypt(ciphertext)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(msgIn, msgOut) {
				t.Fatalf("plaintext differ, %x %x", msgIn, msgOut)
			}
		}
	}
}

func TestDoubleRatchetOutOfOrder(t *testing.T) {
	alice, bob := testDoubleRatchetSetup(t)
	actions := []struct {
		sender   *DoubleRatchet
		receiver *DoubleRatchet
		msgs     int
	}{
		{alice, bob, 2},
		{bob, alice, 3},
		{alice, bob, 5},
		{bob, alice, 7},
		{alice, bob, 11},
		{bob, alice, 19},
		{alice, bob, 23},
		{bob, alice, 29},
	}

	for _, action := range actions {
		var err error
		ciphertexts := make([][]byte, action.msgs)

		for i := 0; i < action.msgs; i++ {
			msgIn := make([]byte, 16)
			if _, err := rand.Read(msgIn); err != nil {
				t.Fatal(err)
			}

			ciphertexts[i], err = action.sender.Encrypt(msgIn)
			if err != nil {
				t.Fatal(err)
			}
		}

		norand.Shuffle(len(ciphertexts), func(i, j int) {
			ciphertexts[i], ciphertexts[j] = ciphertexts[j], ciphertexts[i]
		})

		for _, ciphertext := range ciphertexts {
			_, err = action.receiver.Decrypt(ciphertext)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
}

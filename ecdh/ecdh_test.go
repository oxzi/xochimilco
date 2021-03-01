// SPDX-FileCopyrightText: 2021 Alvar Penning
//
// SPDX-License-Identifier: GPL-3.0-or-later

package ecdh

import (
	"bytes"
	"crypto/ed25519"
	"math/rand"
	"reflect"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func generateKeys(t *testing.T) (ap, bp ed25519.PublicKey, as, bs ed25519.PrivateKey) {
	r := rand.New(rand.NewSource(23))

	alicePub, alicePriv, err := ed25519.GenerateKey(r)
	if err != nil {
		t.Fatal(err)
	}

	bobPub, bobPriv, err := ed25519.GenerateKey(r)
	if err != nil {
		t.Fatal(err)
	}

	return alicePub, bobPub, alicePriv, bobPriv
}

func generateEphKeys(t *testing.T) (ae, be []byte) {
	rand.Seed(23)

	for _, e := range []*[]byte{&ae, &be} {
		*e = make([]byte, curve25519.ScalarSize)

		if n, err := rand.Read(*e); err != nil {
			t.Fatal(err)
		} else if n != curve25519.ScalarSize {
			t.Fatalf("read %d bytes, expected %d", n, curve25519.ScalarSize)
		}
	}

	return
}

func TestEcdhUsual(t *testing.T) {
	alicePub, bobPub, alicePriv, bobPriv := generateKeys(t)
	aliceEphPriv, bobEphPriv := generateEphKeys(t)

	// Alice generates a message for Bob.
	aliceMsg, err := Exchange(alicePriv, aliceEphPriv)
	if err != nil {
		t.Fatal(err)
	}

	// Bob generates a message for Alice.
	bobMsg, err := Exchange(bobPriv, bobEphPriv)
	if err != nil {
		t.Fatal(err)
	}

	// Alice checks the message and derives the shared secret.
	if !bytes.Equal(bobPub, bobMsg.PublicIdentityKey) {
		t.Fatalf("calculated public key %x, expected %x", bobMsg.PublicIdentityKey, bobPub)
	}

	aliceSk, err := bobMsg.SessionKey(aliceEphPriv)
	if err != nil {
		t.Fatal(err)
	}

	// Bob checks the message and derives the shared secret.
	if !bytes.Equal(alicePub, aliceMsg.PublicIdentityKey) {
		t.Fatalf("calculated public key %x, expected %x", aliceMsg.PublicIdentityKey, alicePub)
	}

	bobSk, err := aliceMsg.SessionKey(bobEphPriv)
	if err != nil {
		t.Fatal(err)
	}

	// Compare the secret session keys.
	if !bytes.Equal(aliceSk, bobSk) {
		t.Fatalf("session keys differ: %x, %x", aliceSk, bobSk)
	}
}

func TestEcdhFaulty(t *testing.T) {
	alicePub, bobPub, alicePriv, bobPriv := generateKeys(t)
	aliceEphPriv, bobEphPriv := generateEphKeys(t)

	// Alice generates a message for Bob.
	aliceMsg, err := Exchange(alicePriv, aliceEphPriv)
	if err != nil {
		t.Fatal(err)
	}

	// Bob generates a message for Alice.
	bobMsg, err := Exchange(bobPriv, bobEphPriv)
	if err != nil {
		t.Fatal(err)
	}

	// Flip some bits in both messages
	aliceMsg.PublicIdentityKey[0] ^= 0xFF
	bobMsg.PublicEphemeralKey[0] ^= 0xFF

	// Alice and Bob try to create the session secret.
	if !bytes.Equal(bobPub, bobMsg.PublicIdentityKey) {
		return
	}

	aliceSk, err := bobMsg.SessionKey(aliceEphPriv)
	if err != nil {
		return
	}

	if !bytes.Equal(alicePub, aliceMsg.PublicIdentityKey) {
		return
	}
	bobSk, err := aliceMsg.SessionKey(bobEphPriv)
	if err != nil {
		return
	}

	if bytes.Equal(aliceSk, bobSk) {
		t.Fatal("identical session keys could be created")
	}
}

func TestMessageEncoding(t *testing.T) {
	_, _, alicePriv, _ := generateKeys(t)
	aliceEphPriv, _ := generateEphKeys(t)

	msg, err := Exchange(alicePriv, aliceEphPriv)
	if err != nil {
		t.Fatal(err)
	}

	msgBytes := msg.Bytes()
	if len(msgBytes) != ExchangeMessageSize {
		t.Fatalf("received %d bytes, expected %d", len(msgBytes), ExchangeMessageSize)
	}

	msg2, err := FromBytes(msgBytes)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(msg, msg2) {
		t.Fatal("messages differ")
	}
}

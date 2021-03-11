// SPDX-FileCopyrightText: 2021 Alvar Penning
//
// SPDX-License-Identifier: GPL-3.0-or-later

package xochimilco

import (
	"crypto/ed25519"
	"testing"
)

func TestSessionPingPong(t *testing.T) {
	// Alice and Bob already know the other party's public key.
	alicePub, alicePriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	bobPub, bobPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	alice := Session{
		IdentityKey: alicePriv,
		VerifyPeer: func(peer ed25519.PublicKey) (valid bool) {
			return peer.Equal(bobPub)
		},
	}

	bob := Session{
		IdentityKey: bobPriv,
		VerifyPeer: func(peer ed25519.PublicKey) (valid bool) {
			return peer.Equal(alicePub)
		},
	}

	// Alice starts by offering Bob to upgrade the connection.
	offerMsg, err := alice.Offer()
	if err != nil {
		t.Fatal(err)
	}

	// Bob acknowledges Alice's offer.
	ackMsg, err := bob.Acknowledge(offerMsg)
	if err != nil {
		t.Fatal(err)
	}

	// Alice evaluates Bob's acknowledgement.
	isEstablished, isClosed, plaintext, err := alice.Receive(ackMsg)
	if err != nil {
		t.Fatal(err)
	} else if !isEstablished || isClosed || len(plaintext) > 0 {
		t.Fatal("invalid message")
	}

	// Now we have an established connection.
	// Let's exchange some very important messages.
	messages := []struct {
		sender    Session
		receiver  Session
		plaintext string
	}{
		{alice, bob, "hello bob"},
		{alice, bob, "how are you?"},
		{bob, alice, "hej alice! thanks, I'm fine."},
		{alice, bob, "nice"},
		{bob, alice, "nice"},
		{alice, bob, "nice"},
		{alice, bob, "≽(◔ _ ◔)≼"},
		{bob, alice, "nice"},
		{bob, alice, "we have nothing more to say to each other, do we?"},
		{alice, bob, "≽(; _ ;)≼"},
	}

	for _, message := range messages {
		dataMsg, err := message.sender.Send([]byte(message.plaintext))
		if err != nil {
			t.Fatal(err)
		}

		isEstablished, isClosed, plaintext, err := message.receiver.Receive(dataMsg)
		if err != nil {
			t.Fatal(err)
		} else if isEstablished || isClosed {
			t.Fatal("invalid message")
		} else if message.plaintext != string(plaintext) {
			t.Fatal("plaintext differs")
		}
	}

	// Finally, Alice closes her Session...
	closeMsg, err := alice.Close()
	if err != nil {
		t.Fatal(err)
	}

	// ...and tells Bob to do the same.
	isEstablished, isClosed, plaintext, err = bob.Receive(closeMsg)
	if err != nil {
		t.Fatal(err)
	} else if isEstablished || !isClosed || len(plaintext) > 0 {
		t.Fatal("invalid message")
	}

	_, err = bob.Close()
	if err != nil {
		t.Fatal(err)
	}
}

func TestSessionInvalidVerifyBob(t *testing.T) {
	// Alice and Bob already know the other party's public key.
	_, alicePriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	_, bobPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	alice := Session{
		IdentityKey: alicePriv,
		VerifyPeer: func(peer ed25519.PublicKey) (valid bool) {
			return false
		},
	}

	bob := Session{
		IdentityKey: bobPriv,
		VerifyPeer: func(peer ed25519.PublicKey) (valid bool) {
			return false
		},
	}

	// Alice starts by offering Bob to upgrade the connection.
	offerMsg, err := alice.Offer()
	if err != nil {
		t.Fatal(err)
	}

	// Bob acknowledges Alice's offer. However, Bob's verification fails.
	_, err = bob.Acknowledge(offerMsg)
	if err == nil {
		t.Fatal("should fail")
	}
}

func TestSessionInvalidVerifyAlice(t *testing.T) {
	// Alice and Bob already know the other party's public key.
	alicePub, alicePriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	_, bobPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	alice := Session{
		IdentityKey: alicePriv,
		VerifyPeer: func(peer ed25519.PublicKey) (valid bool) {
			return false
		},
	}

	bob := Session{
		IdentityKey: bobPriv,
		VerifyPeer: func(peer ed25519.PublicKey) (valid bool) {
			return peer.Equal(alicePub)
		},
	}

	// Alice starts by offering Bob to upgrade the connection.
	offerMsg, err := alice.Offer()
	if err != nil {
		t.Fatal(err)
	}

	// Bob acknowledges Alice's offer.
	ackMsg, err := bob.Acknowledge(offerMsg)
	if err != nil {
		t.Fatal(err)
	}

	// Alice evaluates Bob's acknowledgement.
	// But wait, Alice's verification fails.
	_, _, _, err = alice.Receive(ackMsg)
	if err == nil {
		t.Fatal("should fail")
	}
}

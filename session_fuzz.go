// SPDX-FileCopyrightText: 2021 Alvar Penning
//
// SPDX-License-Identifier: GPL-3.0-or-later

// +build gofuzz

// This file fuzzes a Session with go-fuzz.

package xochimilco

import (
	"crypto/ed25519"
	"strings"
)

func Fuzz(data []byte) int {
	if len(data) == 0 {
		return 0
	}

	mode := data[0] % 8
	data = data[1:]

	if !strings.HasPrefix(string(data), Prefix) {
		return -1
	}

	alicePub, alicePriv, _ := ed25519.GenerateKey(nil)
	bobPub, bobPriv, _ := ed25519.GenerateKey(nil)

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

	msg := Prefix + string(data) + Suffix

	if mode == 0 {
		_, _, _, _ = alice.Receive(msg)
		_, _, _, _ = bob.Receive(msg)
	}

	offerMsg, err := alice.Offer()
	if err != nil {
		panic(err)
	}

	if mode == 1 {
		_, _, _, _ = alice.Receive(msg)
		_, _, _, _ = bob.Receive(msg)
	}

	ackMsg, err := bob.Acknowledge(offerMsg)
	if err != nil {
		panic(err)
	}

	if mode == 2 {
		_, _, _, _ = alice.Receive(msg)
		_, _, _, _ = bob.Receive(msg)
	}

	isEstablished, isClosed, plaintext, err := alice.Receive(ackMsg)
	if err != nil {
		panic(err)
	} else if !isEstablished || isClosed || len(plaintext) > 0 {
		panic("invalid message")
	}

	if mode == 2 {
		_, _, _, _ = alice.Receive(msg)
		_, _, _, _ = bob.Receive(msg)
	}

	dataMsg, err := alice.Send([]byte("hello bob"))
	if err != nil {
		panic(err)
	}

	if mode == 3 {
		_, _, _, _ = alice.Receive(msg)
		_, _, _, _ = bob.Receive(msg)
	}

	isEstablished, isClosed, _, err = bob.Receive(dataMsg)
	if err != nil {
		panic(err)
	} else if isEstablished || isClosed {
		panic("invalid message")
	}

	if mode == 4 {
		_, _, _, _ = alice.Receive(msg)
		_, _, _, _ = bob.Receive(msg)
	}

	closeMsg, err := alice.Close()
	if err != nil {
		panic(err)
	}

	if mode == 5 {
		_, _, _, _ = alice.Receive(msg)
		_, _, _, _ = bob.Receive(msg)
	}

	isEstablished, isClosed, _, err = bob.Receive(closeMsg)
	if err != nil {
		panic(err)
	} else if isEstablished || !isClosed {
		panic("invalid message")
	}

	if mode == 6 {
		_, _, _, _ = alice.Receive(msg)
		_, _, _, _ = bob.Receive(msg)
	}

	_, err = bob.Close()
	if err != nil {
		panic(err)
	}

	if mode == 7 {
		_, _, _, _ = alice.Receive(msg)
		_, _, _, _ = bob.Receive(msg)
	}

	return 0
}

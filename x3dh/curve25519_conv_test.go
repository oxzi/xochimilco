// SPDX-FileCopyrightText: 2021 Alvar Penning
//
// SPDX-License-Identifier: GPL-3.0-or-later

// This file contains test for the Curve25519 conversion functions from Filippo
// Valsorda's age tool. Those are mostly written to understand how to handle
// this functions and how to perform an ECDH key exchange based on Ed25519.

package x3dh

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func TestCurve25519Duality(t *testing.T) {
	edPub, edPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	xPub := ed25519PublicKeyToCurve25519(edPub)
	xPriv := ed25519PrivateKeyToCurve25519(edPriv)

	xPubDeriv, err := curve25519.X25519(xPriv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(xPub, xPubDeriv) {
		t.Fatalf("public keys differ, %x %x", xPub, xPubDeriv)
	}
}

func TestEd25519Ecdh(t *testing.T) {
	aliceEdPub, aliceEdPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	bobEdPub, bobEdPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	// Alice and Bob are exchanging their public keys here.

	// Alice's calculation
	aliceXPriv := ed25519PrivateKeyToCurve25519(aliceEdPriv)
	bobXPub := ed25519PublicKeyToCurve25519(bobEdPub)

	aliceSk, err := curve25519.X25519(aliceXPriv, bobXPub)
	if err != nil {
		t.Fatal(err)
	}

	// Bob's calculation
	bobXPriv := ed25519PrivateKeyToCurve25519(bobEdPriv)
	aliceXPub := ed25519PublicKeyToCurve25519(aliceEdPub)

	bobSk, err := curve25519.X25519(bobXPriv, aliceXPub)
	if err != nil {
		t.Fatal(err)
	}

	// Compare secret keys
	if !bytes.Equal(aliceSk, bobSk) {
		t.Fatalf("secret keys differ, %x %x", aliceSk, bobSk)
	}
}

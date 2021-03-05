// SPDX-FileCopyrightText: 2021 Alvar Penning
//
// SPDX-License-Identifier: GPL-3.0-or-later

package doubleratchet

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// dhKeyPair generates a new Elliptic Curve Diffie-Hellman key pair based on
// Curve25519, RFC 7748.
//
// The Double Ratchet Algorithm specification names this function GENERATE_DH.
func dhKeyPair() (pubKey, privKey []byte, err error) {
	privKey = make([]byte, curve25519.ScalarSize)
	if _, err = rand.Read(privKey); err != nil {
		return
	}

	pubKey, err = curve25519.X25519(privKey, curve25519.Basepoint)
	return
}

// dh calculates an Elliptic Curve Diffie-Hellman shared secret between a
// private key and another peer's public key based on Curve25519, RFC 7748.
//
// The Double Ratchet Algorithm specification names this function DH.
func dh(privKey, pubKey []byte) (sharedSec []byte, err error) {
	if len(privKey) != curve25519.ScalarSize {
		return nil, fmt.Errorf("private key MUST be of %d bytes", curve25519.ScalarSize)
	} else if len(pubKey) != curve25519.PointSize {
		return nil, fmt.Errorf("public key MUST be of %d bytes", curve25519.PointSize)
	}

	return curve25519.X25519(privKey, pubKey)
}

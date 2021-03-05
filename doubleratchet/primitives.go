// SPDX-FileCopyrightText: 2021 Alvar Penning
//
// SPDX-License-Identifier: GPL-3.0-or-later

package doubleratchet

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
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

// chainKdf returns a pair (32-byte chain key, 32-byte message key) as the
// output of applying a KDF keyed by a 32-byte chain key to some constant.
//
// Internally an HMAC with SHA-512 is used to derive the two keys from the
// previous chain key. The constant is 0x01.
//
// The Double Ratchet Algorithm specification names this function KDF_CK.
func chainKdf(ckIn []byte) (ckOut, msgKey []byte, err error) {
	if len(ckIn) != 32 {
		return nil, nil, fmt.Errorf("input chain key MUST be of 32 bytes")
	}

	mac := hmac.New(sha512.New, ckIn)
	if _, err = mac.Write([]byte{0x01}); err != nil {
		return
	}

	out := mac.Sum(nil)
	ckOut, msgKey = out[:32], out[32:]

	return
}

// rootKdf returns a pair (32-byte root key, 32-byte chain key) as the output of
// applying a KDF keyed by a 32-byte root key to a Diffie-Hellman output.
//
// Internally an HKDF with SHA-512 is used, using dh as the secret, rkIn as the
// salt and 0x02 as the info.
//
// The Double Ratchet Algorithm specification names this function KDF_RK.
func rootKdf(rkIn, dh []byte) (rkOut, ck []byte, err error) {
	if len(rkIn) != 32 {
		return nil, nil, fmt.Errorf("input chain key MUST be of 32 bytes")
	}

	kdf := hkdf.New(sha512.New, dh, rkIn, []byte{0x02})
	for _, k := range []*[]byte{&rkOut, &ck} {
		*k = make([]byte, 32)
		if _, err = io.ReadFull(kdf, *k); err != nil {
			return
		}
	}

	return
}

// SPDX-FileCopyrightText: 2021 Alvar Penning
//
// SPDX-License-Identifier: GPL-3.0-or-later

// Package ecdh implements a simple Elliptic-curve Diffie-Hellman (ECDH) key
// agreement based on Ed25519 and X25519.
//
// Therefore each party needs an identity key (Ed25519). For each key exchange,
// an ephemeral X25519 key is generated to perform the key exchange. This
// ephemeral key is signed by the long time identity key.
//
// This extends the Curve25519 based ECDH described in RFC 7748 by a short lived
// ephemeral key for forward secrecy.
package ecdh

import (
	"crypto/ed25519"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// ExchangeMessageSize is the length of an encoded ExchangeMessage.
const ExchangeMessageSize = ed25519.PublicKeySize + curve25519.PointSize + ed25519.SignatureSize

// ExchangeMessage are exchanged between two peers including the public part of
// the Identity key and the public ephemeral key, to be used for the ECDH key
// exchange. The signature is an Ed25519 signature of the ephemeral key by the
// identity key.
type ExchangeMessage struct {
	PublicIdentityKey  []byte
	PublicEphemeralKey []byte
	Signature          []byte
}

// Bytes of an ExchangeMessage to be sent over the network.
func (msg ExchangeMessage) Bytes() []byte {
	return append(append(msg.PublicIdentityKey, msg.PublicEphemeralKey...), msg.Signature...)
}

// FromBytes parses an ExchangeMessage from its encoded bytes form.
func FromBytes(data []byte) (msg ExchangeMessage, err error) {
	if l := len(data); l != ExchangeMessageSize {
		err = fmt.Errorf("received %d bytes, expected %d", l, ExchangeMessageSize)
		return
	}

	msg.PublicIdentityKey = data[:ed25519.PublicKeySize]
	msg.PublicEphemeralKey = data[ed25519.PublicKeySize : ed25519.PublicKeySize+curve25519.PointSize]
	msg.Signature = data[ed25519.PublicKeySize+curve25519.PointSize:]
	return
}

// Exchange creates an ExchangeMessage from an identity key and an ephemeral
// key. The first one must be an Ed25519 private key. The ephemeral key must be
// a private X25519 key. The latter can be generated from 32 random bytes.
func Exchange(identityKey ed25519.PrivateKey, ephemeralKey []byte) (msg ExchangeMessage, err error) {
	msg.PublicIdentityKey = identityKey.Public().(ed25519.PublicKey)
	msg.PublicEphemeralKey, err = curve25519.X25519(ephemeralKey, curve25519.Basepoint)
	if err != nil {
		return
	}
	msg.Signature = ed25519.Sign(identityKey, msg.PublicEphemeralKey)
	return
}

// SessionKey derived from this peer's ephemeral key and the received
// ExchangeMessage. The client software MUST check the public identity key in
// the ExchangeMessage struct first.
func (msg ExchangeMessage) SessionKey(ephemeralKey []byte) (key []byte, err error) {
	if !ed25519.Verify(msg.PublicIdentityKey, msg.PublicEphemeralKey, msg.Signature) {
		return nil, fmt.Errorf("invalid identity key signature")
	}

	return curve25519.X25519(ephemeralKey, msg.PublicEphemeralKey)
}

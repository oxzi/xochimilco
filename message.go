// SPDX-FileCopyrightText: 2021 Alvar Penning
//
// SPDX-License-Identifier: GPL-3.0-or-later

package xochimilco

import (
	"crypto/subtle"
	"encoding"
	"encoding/base64"
	"fmt"
	"strings"
)

// messageType identifies the message's type resp. its state and desired action.
type messageType byte

const (
	_ messageType = iota

	// sessOffer is Alice's initial message, asking Bob to upgrade their
	// conversation by advertising her X3DH parameters.
	sessOffer

	// sessAck is Bob's first answer, including his X3DH parameters as well as
	// a first nonsense message as a ciphertext to setup the Double Ratchet.
	sessAck

	// sessData are encrypted messages exchanged between the both parties.
	sessData

	// sessClose cancels a Xochimilco session. This is possible in each state
	// and might occur due to a regular closing as well as rejecting an identity
	// key.
	// A MITM can also send this. However, a MITM can also drop messages.
	sessClose

	// Prefix indicates the beginning of an encoded message.
	Prefix string = "!XO!"

	// Suffix indicates the end of an encoded message.
	Suffix string = "!OX!"
)

// marshalMessage creates the entire encoded message from a struct.
func marshalMessage(t messageType, m encoding.BinaryMarshaler) (out string, err error) {
	b := new(strings.Builder)

	_, _ = fmt.Fprint(b, Prefix)
	_, _ = fmt.Fprint(b, int(t))

	data, err := m.MarshalBinary()
	if err != nil {
		return
	}

	b64 := base64.NewEncoder(base64.StdEncoding, b)
	if _, err = b64.Write(data); err != nil {
		return
	}
	if err = b64.Close(); err != nil {
		return
	}

	_, _ = fmt.Fprint(b, Suffix)

	out = b.String()
	return
}

// unmarshalMessage recreates the struct for an encoded message.
func unmarshalMessage(in string) (t messageType, m interface{}, err error) {
	if !strings.HasPrefix(in, Prefix) || !strings.HasSuffix(in, Suffix) {
		err = fmt.Errorf("message string misses pre- and/or suffix")
		return
	}

	switch t = messageType(in[len(Prefix)] - '0'); t {
	case sessOffer:
		m = new(offerMessage)
	case sessAck:
		m = new(ackMessage)
	case sessData:
		m = new(dataMessage)
	case sessClose:
		m = new(closeMessage)
	default:
		err = fmt.Errorf("unsupported message type %d", t)
		return
	}

	data, err := base64.StdEncoding.DecodeString(in[len(Prefix)+1 : len(in)-len(Suffix)])
	if err != nil {
		return
	}

	err = m.(encoding.BinaryUnmarshaler).UnmarshalBinary(data)

	return
}

// offerMessage is the initial sessOffer message, announcing Alice's public
// Ed25519 Identity Key (32 byte), her X25519 signed prekey (32 byte), and the
// signature (64 bytes).
type offerMessage struct {
	idKey []byte
	spKey []byte
	spSig []byte
}

func (msg offerMessage) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 32+32+64)

	copy(data[:32], msg.idKey)
	copy(data[32:64], msg.spKey)
	copy(data[64:], msg.spSig)

	return
}

func (msg *offerMessage) UnmarshalBinary(data []byte) (err error) {
	if len(data) != 32+32+64 {
		return fmt.Errorf("sessOffer payload MUST be of 128 byte")
	}

	msg.idKey = make([]byte, 32)
	msg.spKey = make([]byte, 32)
	msg.spSig = make([]byte, 64)

	copy(msg.idKey, data[:32])
	copy(msg.spKey, data[32:64])
	copy(msg.spSig, data[64:])

	return
}

// ackMessage is the second sessAck message for Bob to acknowledge Alice's
// sessOffer, finishing X3DH and starting his Double Ratchet. The fields are
// Bob's Ed25519 public key (32 byte), his ephemeral X25519 key (32 byte) and a
// nonsense initial ciphertext.
type ackMessage struct {
	idKey  []byte
	eKey   []byte
	cipher []byte
}

func (msg ackMessage) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 32+32+len(msg.cipher))

	copy(data[:32], msg.idKey)
	copy(data[32:64], msg.eKey)
	copy(data[64:], msg.cipher)

	return
}

func (msg *ackMessage) UnmarshalBinary(data []byte) (err error) {
	if len(data) <= 32+32 {
		return fmt.Errorf("sessAck payload MUST be >= 64 byte")
	}

	msg.idKey = make([]byte, 32)
	msg.eKey = make([]byte, 32)
	msg.cipher = make([]byte, len(data)-64)

	copy(msg.idKey, data[:32])
	copy(msg.eKey, data[32:64])
	copy(msg.cipher, data[64:])

	return
}

// dataMessage is the sessData message for the bidirectional exchange of
// encrypted ciphertext. Thus, its length is dynamic.
type dataMessage []byte

func (msg dataMessage) MarshalBinary() (data []byte, err error) {
	return msg, nil
}

func (msg *dataMessage) UnmarshalBinary(data []byte) (err error) {
	*msg = data
	return
}

// closeMessage is the bidirectional sessClose message. Its payload ix 0xff.
type closeMessage []byte

func (msg closeMessage) MarshalBinary() (data []byte, err error) {
	return msg, nil
}

func (msg *closeMessage) UnmarshalBinary(data []byte) (err error) {
	if subtle.ConstantTimeCompare(data, []byte{0xff}) != 1 {
		err = fmt.Errorf("sessClose has an inavlid payload")
	} else {
		*msg = data
	}

	return
}

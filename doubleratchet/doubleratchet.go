// SPDX-FileCopyrightText: 2021 Alvar Penning
//
// SPDX-License-Identifier: GPL-3.0-or-later

package doubleratchet

import (
	"crypto/subtle"
)

// Header represents an unencrypted Double Ratchet message header.
//
// A header contains the sender's current DH ratchet public key, the previous
// chain length (PN), and the this message's chain number (N). The Double
// Ratchet Algorithm specification names this as HEADER.
type Header struct {
	DhPub  []byte
	PrevNo int
	MsgNo  int
}

// DoubleRatchet implements the Double Ratchet Algorithm.
type DoubleRatchet struct {
	associatedData []byte

	dhr *dhRatchet

	peerDhPub    []byte
	chainKeySend []byte
	chainKeyRecv []byte

	sendNo int
	recvNo int
}

// CreateActive creates a Double Ratchet for the active part, Alice.
func CreateActive(sessKey, associatedData, peerDhPub []byte) (dr *DoubleRatchet, err error) {
	dhr, err := dhRatchetActive(sessKey, peerDhPub)
	if err != nil {
		return
	}

	dr = &DoubleRatchet{
		associatedData: associatedData,
		dhr:            dhr,
		peerDhPub:      peerDhPub,
	}
	return
}

// CreatePassive creates a Double Ratchet for the passive part, Bob.
func CreatePassive(sessKey, associatedData, dhPub, dhPriv []byte) (dr *DoubleRatchet, err error) {
	dhr, err := dhRatchetPassive(sessKey, dhPub, dhPriv)
	if err != nil {
		return
	}

	dr = &DoubleRatchet{
		associatedData: associatedData,
		dhr:            dhr,
	}
	return
}

// dhStep performs a Diffie-Hellman ratchet step.
//
// This is performed automatically if the other party's DH ratchet has proceeded
// or for the active part's initial encrypted message.
func (dr *DoubleRatchet) dhStep() (err error) {
	dr.sendNo = 0
	dr.recvNo = 0

	_, dr.chainKeySend, dr.chainKeyRecv, err = dr.dhr.step(dr.peerDhPub)
	return
}

// Encrypt a plaintext message for the other party.
func (dr *DoubleRatchet) Encrypt(plaintext []byte) (header Header, ciphertext []byte, err error) {
	if dr.chainKeySend == nil {
		err = dr.dhStep()
		if err != nil {
			return
		}
	}

	var msgKey []byte
	dr.chainKeySend, msgKey, err = chainKdf(dr.chainKeySend)
	if err != nil {
		return
	}

	header = Header{
		DhPub:  dr.dhr.dhPub,
		PrevNo: 0, // TODO
		MsgNo:  dr.sendNo,
	}
	dr.sendNo++

	ciphertext, err = encrypt(msgKey, plaintext, dr.associatedData)
	return
}

// Decrypt a ciphertext from the other party.
//
// The encryption is an AEAD encryption. Thus, a changed message should be
// detected and result in an error.
func (dr *DoubleRatchet) Decrypt(header Header, ciphertext []byte) (plaintext []byte, err error) {
	// TODO: try skipped messages first

	if subtle.ConstantTimeCompare(header.DhPub, dr.peerDhPub) != 1 {
		dr.peerDhPub = header.DhPub

		err = dr.dhStep()
		if err != nil {
			return
		}
	}

	var msgKey []byte
	dr.chainKeyRecv, msgKey, err = chainKdf(dr.chainKeyRecv)
	if err != nil {
		return
	}
	dr.recvNo++

	plaintext, err = decrypt(msgKey, ciphertext, dr.associatedData)
	return
}

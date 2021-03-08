// SPDX-FileCopyrightText: 2021 Alvar Penning
//
// SPDX-License-Identifier: GPL-3.0-or-later

package doubleratchet

import (
	"crypto/subtle"
	"fmt"
)

// maxSkip for each receiving chain.
const maxSkip int = 32

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

	sendNo     int
	recvNo     int
	prevSendNo int

	// dhPub -> recvNo -> msgKey
	skippedMsgKeys map[[32]byte]map[int][]byte
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
		skippedMsgKeys: make(map[[32]byte]map[int][]byte),
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
		skippedMsgKeys: make(map[[32]byte]map[int][]byte),
	}
	return
}

// dhStep performs a Diffie-Hellman ratchet step.
//
// This is performed automatically if the other party's DH ratchet has proceeded
// or for the active part's initial encrypted message.
func (dr *DoubleRatchet) dhStep() (err error) {
	dr.prevSendNo = dr.sendNo
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
		PrevNo: dr.prevSendNo,
		MsgNo:  dr.sendNo,
	}
	dr.sendNo++

	ciphertext, err = encrypt(msgKey, plaintext, dr.associatedData)
	return
}

// skipMsgKeys caches future message keys in the current receiving chain.
//
// This might be necessary if received messages are either lost or out of order.
func (dr *DoubleRatchet) skipMsgKeys(until int) (err error) {
	if dr.recvNo+maxSkip < until {
		return fmt.Errorf("cannot skip until %d, maximum is %d", until, dr.recvNo+maxSkip)
	}

	// Cannot skip messages without an existing receiving chain. This happens in
	// an initial state before the first complete key exchange.
	if dr.chainKeyRecv == nil {
		return
	}

	for ; dr.recvNo < until; dr.recvNo++ {
		var (
			msgKey  []byte
			dhPubId [32]byte
			subMap  map[int][]byte
			ok      bool
		)

		dr.chainKeyRecv, msgKey, err = chainKdf(dr.chainKeyRecv)
		if err != nil {
			return
		}

		copy(dhPubId[:], dr.peerDhPub)
		subMap, ok = dr.skippedMsgKeys[dhPubId]
		if !ok {
			subMap = make(map[int][]byte)
		}

		subMap[dr.recvNo] = msgKey
		dr.skippedMsgKeys[dhPubId] = subMap
	}

	return
}

// Decrypt a ciphertext from the other party.
//
// The encryption is an AEAD encryption. Thus, a changed message should be
// detected and result in an error.
func (dr *DoubleRatchet) Decrypt(header Header, ciphertext []byte) (plaintext []byte, err error) {
	if subtle.ConstantTimeCompare(header.DhPub, dr.peerDhPub) != 1 {
		err = dr.skipMsgKeys(header.PrevNo)
		if err != nil {
			return
		}

		dr.peerDhPub = header.DhPub

		err = dr.dhStep()
		if err != nil {
			return
		}
	}

	var msgKey []byte
	switch {
	case header.MsgNo < dr.recvNo:
		var dhPubId [32]byte
		copy(dhPubId[:], header.DhPub)

		subMap, ok := dr.skippedMsgKeys[dhPubId]
		if !ok {
			return nil, fmt.Errorf("old message was not cached")
		}

		msgKey, ok = subMap[header.MsgNo]
		if !ok {
			return nil, fmt.Errorf("old message was not cached")
		}

		delete(subMap, header.MsgNo)
		if len(subMap) == 0 {
			delete(dr.skippedMsgKeys, dhPubId)
		}

	case header.MsgNo > dr.recvNo:
		err = dr.skipMsgKeys(header.MsgNo)
		if err != nil {
			return
		}
		fallthrough

	case header.MsgNo == dr.recvNo:
		dr.chainKeyRecv, msgKey, err = chainKdf(dr.chainKeyRecv)
		if err != nil {
			return
		}
		dr.recvNo++
	}

	plaintext, err = decrypt(msgKey, ciphertext, dr.associatedData)
	return
}

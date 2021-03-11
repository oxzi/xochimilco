// SPDX-FileCopyrightText: 2021 Alvar Penning
//
// SPDX-License-Identifier: GPL-3.0-or-later

package xochimilco

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"github.com/oxzi/xochimilco/doubleratchet"
	"github.com/oxzi/xochimilco/x3dh"
)

// Session between two parties to exchange encrypted messages.
//
// Each party creates a new Session variable configured with their private
// long time identity key and a function callback to verify the other party's
// public identity key.
//
// The active party must start by offering to "upgrade" the current channel
// (Offer). Afterwards, the other party must confirm this step (Acknowledge).
// Once the first party finally receives the acknowledgement (Receive), the
// connection is established.
//
// Now both parties can create encrypted messages directed to the other (Send).
// Furthermore, the Session can be closed again (Close). Incoming messages can
// be inspected and the payload extracted, if present (Receive).
type Session struct {
	// IdentityKey is this node's private Ed25519 identity key.
	//
	// This will only be used within the X3DH key agreement protocol. The other
	// party might want to verify this key's public part.
	IdentityKey ed25519.PrivateKey

	// VerifyPeer is a callback during session initialization to verify the
	// other party's public key.
	//
	// To determine when a key is correct is out of Xochimilco's scope. The key
	// might be either exchanged over another secure channel or a trust on first
	// use (TOFU) principle might be used.
	VerifyPeer func(peer ed25519.PublicKey) (valid bool)

	// private fields //

	// spkPub / spkPriv is the X3DH signed prekey for our opening party.
	spkPub, spkPriv []byte

	// doubleRatchet is the internal Double Ratchet.
	doubleRatchet *doubleratchet.DoubleRatchet
}

// Offer to establish an encrypted Session.
//
// This method MUST be called initially by the active resp. opening party
// (Alice) once. The other party will hopefully Acknowledge this message.
func (sess *Session) Offer() (offerMsg string, err error) {
	spkPub, spkPriv, spkSig, err := x3dh.CreateNewSpk(sess.IdentityKey)
	if err != nil {
		return
	}

	sess.spkPub = spkPub
	sess.spkPriv = spkPriv

	offer := offerMessage{
		idKey: sess.IdentityKey.Public().(ed25519.PublicKey),
		spKey: spkPub,
		spSig: spkSig,
	}
	offerMsg, err = marshalMessage(sessOffer, offer)
	return
}

// Acknowledge to establish an encrypted Session.
//
// This method MUST be called by the passive party (Bob) with the active party's
// (Alice's) offer message. The created acknowledge message MUST be send back.
//
// At this point, this passive part is able to send and receive messages.
func (sess *Session) Acknowledge(offerMsg string) (ackMsg string, err error) {
	msgType, offerIf, err := unmarshalMessage(offerMsg)
	if err != nil {
		return
	} else if msgType != sessOffer {
		err = fmt.Errorf("unexpected message type %d", msgType)
		return
	}
	offer := offerIf.(*offerMessage)

	if !sess.VerifyPeer(offer.idKey) {
		err = fmt.Errorf("verification function refuses public key")
		return
	}

	sessKey, associatedData, ekPub, err := x3dh.CreateInitialMessage(
		sess.IdentityKey, offer.idKey, offer.spKey, offer.spSig)
	if err != nil {
		return
	}

	sess.doubleRatchet, err = doubleratchet.CreateActive(sessKey, associatedData, offer.spKey)
	if err != nil {
		return
	}

	// This will be padded up to 32 bytes for AES-256.
	initialPayload := make([]byte, 23)
	if _, err = rand.Read(initialPayload); err != nil {
		return
	}
	initialCiphertext, err := sess.doubleRatchet.Encrypt(initialPayload)
	if err != nil {
		return
	}

	ack := ackMessage{
		idKey:  sess.IdentityKey.Public().(ed25519.PublicKey),
		eKey:   ekPub,
		cipher: initialCiphertext,
	}
	ackMsg, err = marshalMessage(sessAck, ack)
	return
}

// receiveAck deals with incoming sessAck messages.
//
// The active / opening party receives the other party's acknowledgement and
// tries to establish a Session.
func (sess *Session) receiveAck(ack *ackMessage) (isEstablished bool, err error) {
	if sess.doubleRatchet != nil {
		err = fmt.Errorf("received sessAck while being in an active session")
		return
	}

	if !sess.VerifyPeer(ack.idKey) {
		err = fmt.Errorf("verification function refuses public key")
		return
	}

	sessKey, associatedData, err := x3dh.ReceiveInitialMessage(
		sess.IdentityKey, ack.idKey, sess.spkPriv, ack.eKey)
	if err != nil {
		return
	}

	sess.doubleRatchet, err = doubleratchet.CreatePassive(
		sessKey, associatedData, sess.spkPub, sess.spkPriv)
	if err != nil {
		return
	}

	sess.spkPub, sess.spkPriv = nil, nil

	_, err = sess.doubleRatchet.Decrypt(ack.cipher)
	if err != nil {
		return
	}

	isEstablished = true
	return
}

// receiveData deals with incoming sessData messages.
func (sess *Session) receiveData(data *dataMessage) (plaintext []byte, err error) {
	if sess.doubleRatchet == nil {
		err = fmt.Errorf("received sessData while not being in an active session")
		return
	}

	ciphertext := []byte(*data)
	plaintext, err = sess.doubleRatchet.Decrypt(ciphertext)
	return
}

// Receive an incoming message.
//
// All messages except the passive party's initial offer message MUST be passed
// to this method. The multiple return fields indicate this message's kind.
//
// If the active party receives its first (acknowledge) message, this Session
// will be established; isEstablished. If the other party has signaled to close
// the Session, isClosed is set. This Session MUST then also be closed down. In
// case of an incoming encrypted message, the plaintext field holds its
// decrypted plaintext value. Of course, there might also be an error.
func (sess *Session) Receive(msg string) (isEstablished, isClosed bool, plaintext []byte, err error) {
	msgType, msgIf, err := unmarshalMessage(msg)
	if err != nil {
		return
	}

	switch msgType {
	case sessAck:
		isEstablished, err = sess.receiveAck(msgIf.(*ackMessage))

	case sessData:
		plaintext, err = sess.receiveData(msgIf.(*dataMessage))

	case sessClose:
		isClosed = true

	default:
		err = fmt.Errorf("received an unexpected message type %d", msgType)
	}

	return
}

// Send a message to the other party. The given plaintext byte array will be
// embedded in an encrypted message.
//
// This method is allowed to be called after the initial handshake, Offer resp.
// Acknowledge.
func (sess *Session) Send(plaintext []byte) (dataMsg string, err error) {
	if sess.doubleRatchet == nil {
		err = fmt.Errorf("cannot encrypt data without being in an active session")
		return
	}

	ciphertext, err := sess.doubleRatchet.Encrypt(plaintext)
	if err != nil {
		return
	}

	dataMsg, err = marshalMessage(sessData, dataMessage(ciphertext))
	return
}

// Close this Session and tell the other party to do the same.
//
// This resets the internal state. Thus, the same Session might be reused.
func (sess *Session) Close() (closeMsg string, err error) {
	sess.spkPub, sess.spkPriv = nil, nil
	sess.doubleRatchet = nil

	closeMsg, err = marshalMessage(sessClose, closeMessage{0xff})
	return
}

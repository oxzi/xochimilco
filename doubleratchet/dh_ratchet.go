// SPDX-FileCopyrightText: 2021 Alvar Penning
//
// SPDX-License-Identifier: GPL-3.0-or-later

package doubleratchet

// dhRatchet represents a Diffie-Hellman ratchet.
//
// This really only includes the DH ratchet to create new DH secrets to be used
// for the sending and receiving chain. Those values SHOULD be fed into a KDF
// based on the root key.
type dhRatchet struct {
	dhPub     []byte
	dhPriv    []byte
	peerDhPub []byte

	isActive      bool
	isInitialized bool
}

// dhRatchetActive creates a DH ratchet for the active peer, Alice.
func dhRatchetActive(peerDhPub []byte) (r *dhRatchet, err error) {
	r = &dhRatchet{
		isActive:  true,
		peerDhPub: peerDhPub,
	}

	r.dhPub, r.dhPriv, err = dhKeyPair()
	return
}

// dhRatchetPassive creates a DH ratchet for the passive peer, Bob.
func dhRatchetPassive(dhPub, dhPriv []byte) (r *dhRatchet, err error) {
	r = &dhRatchet{
		isActive: false,
		dhPub:    dhPub,
		dhPriv:   dhPriv,
	}
	return
}

// step performs a DH ratchet step.
//
// First, the other party's secret will be calculated. Second, a new DH key pair
// will be generated with its subsequent secret.
//
// For the active peer's initial step, peerDhPub might be nil. The previously
// set value will not be overwritten.
func (r *dhRatchet) step(peerDhPub []byte) (dhPub, sendKey, recvKey []byte, err error) {
	// The active peer needs to perform a special initial step exactly once.
	if r.isActive && !r.isInitialized {
		dhPub = r.dhPub

		sendKey, err = dh(r.dhPriv, r.peerDhPub)
		if err != nil {
			return
		}

		r.isInitialized = true
		return
	}

	r.peerDhPub = peerDhPub

	// Close up to the other party's state..
	recvKey, err = dh(r.dhPriv, r.peerDhPub)
	if err != nil {
		return
	}

	// ..and proceed ourselves.
	r.dhPub, r.dhPriv, err = dhKeyPair()
	if err != nil {
		return
	}
	dhPub = r.dhPub

	sendKey, err = dh(r.dhPriv, r.peerDhPub)
	return
}

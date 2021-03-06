// SPDX-FileCopyrightText: 2021 Alvar Penning
//
// SPDX-License-Identifier: GPL-3.0-or-later

package x3dh

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func TestX3dh(t *testing.T) {
	aliceIdPub, aliceIdPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	bobIdPub, bobIdPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	// Bob creates and publishes a SPK.
	spkPub, spkPriv, spkSig, err := CreateNewSpk(bobIdPriv)
	if err != nil {
		t.Fatal(err)
	}

	// Alice fetches (bobIdPub, spkPub, spkSig) from Bob / a key server.
	aliceSk, aliceAd, ekPub, err := CreateInitialMessage(aliceIdPriv, bobIdPub, spkPub, spkSig)
	if err != nil {
		t.Fatal(err)
	}

	// Alice contacts Bob with (aliceIdPub, ekPub) and some AEAD ciphertext.
	bobSk, bobAd, err := ReceiveInitialMessage(bobIdPriv, aliceIdPub, spkPriv, ekPub)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(aliceSk, bobSk) {
		t.Errorf("secret keys differ, %x %x", aliceSk, bobSk)
	}
	if !bytes.Equal(aliceAd, bobAd) {
		t.Errorf("associated data differ, %x %x", aliceAd, bobAd)
	}
}

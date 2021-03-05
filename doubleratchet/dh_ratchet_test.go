// SPDX-FileCopyrightText: 2021 Alvar Penning
//
// SPDX-License-Identifier: GPL-3.0-or-later

package doubleratchet

import (
	"bytes"
	"testing"
)

func TestDh(t *testing.T) {
	alicePub, alicePriv, err := dhKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	bobPub, bobPriv, err := dhKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	aliceSec, err := dh(alicePriv, bobPub)
	if err != nil {
		t.Fatal(err)
	}

	bobSec, err := dh(bobPriv, alicePub)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(aliceSec, bobSec) {
		t.Fatalf("Alice's and Bob's secret differ, %v %v", aliceSec, bobSec)
	}
}

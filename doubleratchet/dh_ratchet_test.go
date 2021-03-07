// SPDX-FileCopyrightText: 2021 Alvar Penning
//
// SPDX-License-Identifier: GPL-3.0-or-later

package doubleratchet

import (
	"bytes"
	"testing"
)

func TestDhRatchetPingPong(t *testing.T) {
	bobPub, bobPriv, err := dhKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	alice, err := dhRatchetActive(bobPub)
	if err != nil {
		t.Fatal(err)
	}

	bob, err := dhRatchetPassive(bobPub, bobPriv)
	if err != nil {
		t.Fatal(err)
	}

	var dhPub, sk, rk []byte
	for i := 0; i < 128; i++ {
		r := (map[int]*dhRatchet{0: alice, 1: bob})[i%2]

		skPrev := sk
		dhPub, sk, rk, err = r.step(dhPub)
		if err != nil {
			t.Fatal(err)
		} else if !bytes.Equal(skPrev, rk) {
			t.Errorf("new receive key differs from previous send key, %x %x", rk, skPrev)
		}
	}
}

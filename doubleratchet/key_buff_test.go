// SPDX-FileCopyrightText: 2021 Alvar Penning
//
// SPDX-License-Identifier: GPL-3.0-or-later

package doubleratchet

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestKeyBufferFill(t *testing.T) {
	dhKeys := make([][]byte, maxSkipChains)
	for i := 0; i < len(dhKeys); i++ {
		dhKeys[i] = make([]byte, 32)
		if _, err := rand.Read(dhKeys[i]); err != nil {
			t.Fatal(err)
		}
	}

	kb := newKeyBuffer()

	if _, err := kb.find([]byte{0xFF}, 0); err == nil {
		t.Fatal("found non existing dh map")
	}
	if _, err := kb.find(dhKeys[0], 1); err == nil {
		t.Fatal("found non existing message key")
	}

	for _, dhKey := range dhKeys {
		kb.insert(dhKey, 0, []byte{0})
	}

	if _, err := kb.find([]byte{0xFF}, 0); err == nil {
		t.Fatal("found non existing dh map")
	}
	if _, err := kb.find(dhKeys[0], 1); err == nil {
		t.Fatal("found non existing message key")
	}

	for _, dhKey := range dhKeys {
		if msgKey, err := kb.find(dhKey, 0); err != nil {
			t.Fatal(err)
		} else if !bytes.Equal(msgKey, []byte{0}) {
			t.Fatal("keys differ")
		}
	}

	kb.insert([]byte{0x00}, 0, []byte{0})
	hits := 0
	for _, dhKey := range dhKeys {
		if _, err := kb.find(dhKey, 0); err == nil {
			hits++
		}
	}
	if hits != maxSkipChains-1 {
		t.Fatalf("got %d hits", hits)
	}

	if _, err := kb.find(dhKeys[0], 0); err == nil {
		t.Fatal("first dh keypair should be overwritten")
	}
}

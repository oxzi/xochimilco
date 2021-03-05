// SPDX-FileCopyrightText: 2021 Alvar Penning
//
// SPDX-License-Identifier: GPL-3.0-or-later

package doubleratchet

import (
	"math/rand"
	"testing"
)

func TestChainKdfInput(t *testing.T) {
	testcases := []struct {
		input   []byte
		isError bool
	}{
		{nil, true},
		{[]byte{0x01}, true},
		{[]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20}, false},
	}

	for _, testcase := range testcases {
		_, _, err := chainKdf(testcase.input)
		if (err != nil) != testcase.isError {
			t.Errorf("%v resulted in err %v", testcase.input, err)
		}
	}
}

func TestChainKdfOutput(t *testing.T) {
	rand.Seed(23)

	ckIn := make([]byte, 32)
	if _, err := rand.Read(ckIn); err != nil {
		t.Fatal(err)
	}

	ckOut, msgKey, err := chainKdf(ckIn)
	if err != nil {
		t.Fatal(err)
	} else if len(ckOut) != 32 || len(msgKey) != 32 {
		t.Fatalf("invalid output length, %v %v", ckOut, msgKey)
	}
}

func TestRootKdfInput(t *testing.T) {
	testcases := []struct {
		input   []byte
		isError bool
	}{
		{nil, true},
		{[]byte{0x01}, true},
		{[]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20}, false},
	}

	for _, testcase := range testcases {
		_, _, err := rootKdf(testcase.input, []byte{0x00})
		if (err != nil) != testcase.isError {
			t.Errorf("%v resulted in err %v", testcase.input, err)
		}
	}
}

func TestRootKdfOutput(t *testing.T) {
	rand.Seed(23)

	rkIn := make([]byte, 32)
	dh := make([]byte, 32)
	if _, err := rand.Read(rkIn); err != nil {
		t.Fatal(err)
	} else if _, err := rand.Read(dh); err != nil {
		t.Fatal(err)
	}

	rkOut, ck, err := rootKdf(rkIn, dh)
	if err != nil {
		t.Fatal(err)
	} else if len(rkOut) != 32 || len(ck) != 32 {
		t.Fatalf("invalid output length, %v %v", rkOut, ck)
	}
}

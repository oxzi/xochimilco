// SPDX-FileCopyrightText: 2021 Alvar Penning
//
// SPDX-License-Identifier: GPL-3.0-or-later

package doubleratchet

import (
	"crypto/rand"
	"reflect"
	"testing"
)

func TestHeaderMarshal(t *testing.T) {
	testcases := []struct {
		prevNo  int
		msgNo   int
		isError bool
	}{
		{0, 0, false},
		{1, 2, false},
		{65535, 65535, false},
		{65536, 65535, true},
		{65535, 65536, true},
	}

	for _, testcase := range testcases {
		dhPub := make([]byte, 32)
		if _, err := rand.Read(dhPub); err != nil {
			t.Fatal(err)
		}

		hIn := header{
			dhPub:  dhPub,
			prevNo: testcase.prevNo,
			msgNo:  testcase.msgNo,
		}

		data, err := hIn.marshal()
		if (err != nil) != testcase.isError {
			t.Fatal(err)
		} else if err != nil {
			continue
		}

		hOut, err := parseHeader(data)
		if err != nil {
			t.Fatal(err)
		}

		if !reflect.DeepEqual(hIn, hOut) {
			t.Fatalf("headers differ, %#v %#v", hIn, hOut)
		}
	}
}

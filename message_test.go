// SPDX-FileCopyrightText: 2021 Alvar Penning
//
// SPDX-License-Identifier: GPL-3.0-or-later

package xochimilco

import (
	"encoding"
	"reflect"
	"testing"
)

func TestMessageMarshall(t *testing.T) {
	testcases := []struct {
		t messageType
		m encoding.BinaryMarshaler
	}{
		{
			t: sessOffer,
			m: &offerMessage{
				idKey: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2},
				spKey: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2},
				spSig: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4},
			},
		},
		{
			t: sessInit,
			m: &initMessage{
				idKey:  []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2},
				eKey:   []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2},
				cipher: []byte{1, 2, 3, 4, 5, 6, 7},
			},
		},
		{
			t: sessData,
			m: &dataMessage{1, 2, 3, 4, 5, 6, 7},
		},
		{
			t: sessAbort,
			m: &abortMessage{0xff},
		},
	}

	for _, testcase := range testcases {
		txt, err := marshalMessage(testcase.t, testcase.m)
		if err != nil {
			t.Fatal(err)
		}

		ty, m, err := unmarshalMessage(txt)
		if err != nil {
			t.Fatal(err)
		} else if ty != testcase.t {
			t.Errorf("unexpected type, %d %d", ty, testcase.t)
		} else if !reflect.DeepEqual(m, testcase.m) {
			t.Errorf("messages differ, %#v %#v", m, testcase.m)
		}
	}
}

func TestMessageUnmarshalInvalid(t *testing.T) {
	inputs := []string{
		"",
		Prefix,
		Suffix,
		Suffix + Prefix,
		Prefix + "0" + Suffix,
		Prefix + "1" + Suffix,
		Prefix + "2" + Suffix,
		Prefix + "4" + Suffix,
		Prefix + "5" + Suffix,
		Prefix + "42" + Suffix,
		Prefix + "3💩💩💩" + Suffix,
	}

	for _, input := range inputs {
		_, _, err := unmarshalMessage(input)
		if err == nil {
			t.Errorf("%s did not error", input)
		}
	}
}

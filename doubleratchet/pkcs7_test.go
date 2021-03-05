// SPDX-FileCopyrightText: 2021 Alvar Penning
//
// SPDX-License-Identifier: GPL-3.0-or-later

package doubleratchet

import (
	"bytes"
	"testing"
)

func TestPkcs7Pad(t *testing.T) {
	testcases := []struct {
		dataLen       int
		blockSize     int
		paddedDataLen int
		isError       bool
	}{
		{0, 0, 0, true},
		{23, 1, 24, false},
		{42, 1, 43, false},
		{16, 16, 32, false},
		{23, 16, 32, false},
		{0, 255, 255, false},
		{23, 255, 255, false},
		{255, 255, 510, false},
		{0, 256, 0, true},
	}

	for _, testcase := range testcases {
		data := bytes.Repeat([]byte{0xAA}, testcase.dataLen)
		paddedData, err := pkcs7Pad(data, testcase.blockSize)

		if (err != nil) != testcase.isError {
			t.Errorf("%#v resulted in err %v", testcase, err)
		} else if err != nil {
			continue
		}

		if len(paddedData) != testcase.paddedDataLen {
			t.Errorf("%#v created padded data of length %d", testcase, len(paddedData))
		}
	}
}

func TestPkcs7RoundTrip(t *testing.T) {
	testcases := []struct {
		dataLen   int
		blockSize int
	}{
		{4, 16},
		{8, 16},
		{16, 16},
		{1, 128},
		{64, 128},
		{127, 128},
	}

	for _, testcase := range testcases {
		dataIn := bytes.Repeat([]byte{0xAA}, testcase.dataLen)
		paddedData, err := pkcs7Pad(dataIn, testcase.blockSize)
		if err != nil {
			t.Errorf("%#v cannot be padded, %v", testcase, err)
		}

		dataOut, err := pkcs7Unpad(paddedData, testcase.blockSize)
		if err != nil {
			t.Errorf("%#v cannot be unpadded, %v", testcase, err)
		}

		if !bytes.Equal(dataIn, dataOut) {
			t.Errorf("%#v differs, %v %v", testcase, dataIn, dataOut)
		}
	}
}

func TestPkcs7UnpadInvalid(t *testing.T) {
	data := bytes.Repeat([]byte{0xAA}, 42)
	paddedData, err := pkcs7Pad(data, 16)
	if err != nil {
		t.Fatal(err)
	}

	// invalid total length
	paddedDataInvalidLen := append(paddedData, 0x00)
	if _, err := pkcs7Unpad(paddedDataInvalidLen, 16); err == nil {
		t.Errorf("%v should have failed", paddedDataInvalidLen)
	}

	// invalid suffix, other than last byte
	paddedDataCorrupted := make([]byte, len(paddedData))
	copy(paddedDataCorrupted, paddedData)
	paddedDataCorrupted[len(paddedDataCorrupted)-2] = 0x00
	if _, err := pkcs7Unpad(paddedDataCorrupted, 16); err == nil {
		t.Errorf("%v should have failed", paddedDataCorrupted)
	}

	// invalid suffix, last counter byte
	paddedDataLenCorrupted := make([]byte, len(paddedData))
	copy(paddedDataLenCorrupted, paddedData)
	paddedDataLenCorrupted[len(paddedDataLenCorrupted)-1] = 0x00
	if _, err := pkcs7Unpad(paddedDataLenCorrupted, 16); err == nil {
		t.Errorf("%v should have failed", paddedDataLenCorrupted)
	}
}

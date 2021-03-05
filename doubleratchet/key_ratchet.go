// SPDX-FileCopyrightText: 2021 Alvar Penning
//
// SPDX-License-Identifier: GPL-3.0-or-later

package doubleratchet

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// chainKdf returns a pair (32-byte chain key, 32-byte message key) as the
// output of applying a KDF keyed by a 32-byte chain key to some constant.
//
// Internally an HMAC with SHA-512 is used to derive the two keys from the
// previous chain key. The constant is 0x01.
//
// The Double Ratchet Algorithm specification names this function KDF_CK.
func chainKdf(ckIn []byte) (ckOut, msgKey []byte, err error) {
	if len(ckIn) != 32 {
		return nil, nil, fmt.Errorf("input chain key MUST be of 32 bytes")
	}

	mac := hmac.New(sha512.New, ckIn)
	if _, err = mac.Write([]byte{0x01}); err != nil {
		return
	}

	out := mac.Sum(nil)
	ckOut, msgKey = out[:32], out[32:]

	return
}

// rootKdf returns a pair (32-byte root key, 32-byte chain key) as the output of
// applying a KDF keyed by a 32-byte root key to a Diffie-Hellman output.
//
// Internally an HKDF with SHA-512 is used, using dh as the secret, rkIn as the
// salt and 0x02 as the info.
//
// The Double Ratchet Algorithm specification names this function KDF_RK.
func rootKdf(rkIn, dh []byte) (rkOut, ck []byte, err error) {
	if len(rkIn) != 32 {
		return nil, nil, fmt.Errorf("input chain key MUST be of 32 bytes")
	}

	kdf := hkdf.New(sha512.New, dh, rkIn, []byte{0x02})
	for _, k := range []*[]byte{&rkOut, &ck} {
		*k = make([]byte, 32)
		if _, err = io.ReadFull(kdf, *k); err != nil {
			return
		}
	}

	return
}

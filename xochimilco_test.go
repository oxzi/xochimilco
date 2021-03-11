// SPDX-FileCopyrightText: 2021 Alvar Penning
//
// SPDX-License-Identifier: GPL-3.0-or-later

package xochimilco

import (
	"crypto/ed25519"
	"fmt"
)

func Example() {
	// In this example, Alice and Bob can exchange messages over some chat
	// protocol. Furthermore, they already know each other's public key.
	alicePub, alicePriv, _ := ed25519.GenerateKey(nil)
	bobPub, bobPriv, _ := ed25519.GenerateKey(nil)

	alice := Session{
		IdentityKey: alicePriv,
		VerifyPeer: func(peer ed25519.PublicKey) (valid bool) {
			return peer.Equal(bobPub)
		},
	}
	bob := Session{
		IdentityKey: bobPriv,
		VerifyPeer: func(peer ed25519.PublicKey) (valid bool) {
			return peer.Equal(alicePub)
		},
	}

	// Alice starts by offering Bob to upgrade the connection.
	offerMsg, err := alice.Offer()
	if err != nil {
		panic(err)
	}
	fmt.Printf("A->B\tOFFER\t%s\n", offerMsg)

	// Bob acknowledges Alice's offer.
	ackMsg, err := bob.Acknowledge(offerMsg)
	if err != nil {
		panic(err)
	}
	fmt.Printf("B-A\tACK\t%s\n", ackMsg)

	// Alice evaluates Bob's acknowledgement. This SHOULD be `isEstablished`.
	isEstablished, _, _, err := alice.Receive(ackMsg)
	if err != nil {
		panic(err)
	} else if !isEstablished {
		panic("invalid message")
	}

	// Now we have an established connection.
	// Let's exchange some very important messages.
	dataMsgAlice1, err := alice.Send([]byte("hello bob"))
	if err != nil {
		panic(err)
	}
	dataMsgAlice2, err := alice.Send([]byte("how are you?"))
	if err != nil {
		panic(err)
	}

	// Ops, the messages were reorder on the wired.
	fmt.Printf("A->B\tDATA\t%s", dataMsgAlice2)
	fmt.Printf("A->B\tDATA\t%s", dataMsgAlice1)

	_, _, plaintextAlice2, err := bob.Receive(dataMsgAlice2)
	if err != nil {
		panic(err)
	}
	fmt.Printf("B\tRECV\t%s", plaintextAlice2)

	_, _, plaintextAlice1, err := bob.Receive(dataMsgAlice2)
	if err != nil {
		panic(err)
	}
	fmt.Printf("B\tRECV\t%s", plaintextAlice1)

	// Bob also sends an answer.
	dataMsgBob, err := bob.Send([]byte("hej alice!"))
	if err != nil {
		panic(err)
	}
	fmt.Printf("B->A\tDATA\t%s", dataMsgBob)

	_, _, plaintextBob, err := alice.Receive(dataMsgBob)
	if err != nil {
		panic(err)
	}
	fmt.Printf("A\tRECV\t%s", plaintextBob)

	// Finally, Alice closes her Session...
	closeMsg, err := alice.Close()
	if err != nil {
		panic(err)
	}
	fmt.Printf("A->B\tCLOSE\t%s", closeMsg)

	// ...and tells Bob to do the same.
	_, isClosed, _, err := bob.Receive(closeMsg)
	if err != nil {
		panic(err)
	} else if !isClosed {
		panic("invalid message")
	}

	_, err = bob.Close()
	if err != nil {
		panic(err)
	}
}

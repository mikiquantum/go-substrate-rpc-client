// Go Substrate RPC Client (GSRPC) provides APIs and types around Polkadot and any Substrate-based chain RPC calls
//
// Copyright 2019 Centrifuge GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package types

import (
	"github.com/centrifuge/go-substrate-rpc-client/scale"
)

// Address is a wrapper around an AccountId or an AccountIndex. It is encoded with a prefix in case of an AccountID.
// Basically the Address is encoded as `[ <prefix-byte>, ...publicKey/...bytes ]` as per spec
type Address struct {
	IsAccountID    bool
	AsAccountID    AccountID
	IsAccountIndex bool
	AsAccountIndex AccountIndex
}

// NewAddressFromAccountID creates an Address from the given AccountID (public key)
func NewAddressFromAccountID(b []byte) Address {
	return Address{
		IsAccountID: true,
		AsAccountID: NewAccountID(b),
	}
}

// NewAddressFromHexAccountID creates an Address from the given hex string that contains an AccountID (public key)
func NewAddressFromHexAccountID(str string) (Address, error) {
	b, err := HexDecodeString(str)
	if err != nil {
		return Address{}, err
	}
	return NewAddressFromAccountID(b), nil
}

// NewAddressFromAccountIndex creates an Address from the given AccountIndex
func NewAddressFromAccountIndex(u uint32) Address {
	return Address{
		IsAccountIndex: true,
		AsAccountIndex: AccountIndex(u),
	}
}

func (a *Address) Decode(decoder scale.Decoder) error {
	var sm [32]byte // Reading Address[32]
	err := decoder.Decode(&sm)
	if err != nil {
		return err
	}

	a.AsAccountID = NewAccountID(sm[:])
	a.IsAccountID = true

	return nil
}

func (a Address) Encode(encoder scale.Encoder) error {
	// type of address - public key
	if a.IsAccountID {
		err := encoder.Write(a.AsAccountID[:])
		if err != nil {
			return err
		}

		return nil
	}

	if a.AsAccountIndex > 0xffff {
		err := encoder.PushByte(253)
		if err != nil {
			return err
		}

		return encoder.Encode(a.AsAccountIndex)
	}

	if a.AsAccountIndex >= 0xf0 {
		err := encoder.PushByte(252)
		if err != nil {
			return err
		}

		return encoder.Encode(uint16(a.AsAccountIndex))
	}

	return encoder.Encode(uint8(a.AsAccountIndex))
}

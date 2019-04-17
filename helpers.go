// Copyright 2019 The Bytecoin developers
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

package bytecoin

import (
	"bytes"
	"encoding/hex"
	"fmt"
)

const (
	hashSize      = 32
	publicKeySize = 32
	keyImageSize  = 32
)

type Hash [hashSize]byte

func (h Hash) String() string                  { return hex.EncodeToString(h[:]) }
func (h Hash) IsZero() bool                    { return emptyOrZero(h[:]) }
func (h Hash) MarshalJSON() ([]byte, error)    { return toJSONHex(h[:]), nil }
func (h *Hash) UnmarshalJSON(b []byte) error   { return fromJSONHex(h[:], b) }
func (h Hash) MarshalBinary() ([]byte, error)  { return toBinary(h[:]), nil }
func (h *Hash) UnmarshalBinary(b []byte) error { return fromBinary(h[:], b) }

type PublicKey [publicKeySize]byte

func (pk PublicKey) String() string                  { return hex.EncodeToString(pk[:]) }
func (pk PublicKey) IsZero() bool                    { return emptyOrZero(pk[:]) }
func (pk PublicKey) MarshalJSON() ([]byte, error)    { return toJSONHex(pk[:]), nil }
func (pk *PublicKey) UnmarshalJSON(b []byte) error   { return fromJSONHex(pk[:], b) }
func (pk PublicKey) MarshalBinary() ([]byte, error)  { return toBinary(pk[:]), nil }
func (pk *PublicKey) UnmarshalBinary(b []byte) error { return fromBinary(pk[:], b) }

type KeyImage [keyImageSize]byte

func (k KeyImage) String() string                  { return hex.EncodeToString(k[:]) }
func (k KeyImage) IsZero() bool                    { return emptyOrZero(k[:]) }
func (k KeyImage) MarshalJSON() ([]byte, error)    { return toJSONHex(k[:]), nil }
func (k *KeyImage) UnmarshalJSON(b []byte) error   { return fromJSONHex(k[:], b) }
func (k KeyImage) MarshalBinary() ([]byte, error)  { return toBinary(k[:]), nil }
func (k *KeyImage) UnmarshalBinary(b []byte) error { return fromBinary(k[:], b) }

type HexBlob []byte

func (blob HexBlob) String() string               { return hex.EncodeToString(blob) }
func (blob HexBlob) IsZero() bool                 { return emptyOrZero(blob) }
func (blob HexBlob) MarshalJSON() ([]byte, error) { return toJSONHex(blob), nil }

func (blob *HexBlob) UnmarshalJSON(b []byte) error {
	if len(b) < 2 {
		return fmt.Errorf("hex blob size %v too small", len(b))
	}
	buf := make([]byte, hex.DecodedLen(len(b)-2))
	err := fromJSONHex(buf, b)
	if err != nil {
		return err
	}
	*blob = buf
	return nil
}

func emptyOrZero(b []byte) bool {
	return len(b) == bytes.Count(b, []byte{0})
}

func toJSONHex(b []byte) []byte {
	if emptyOrZero(b) {
		return []byte(`""`)
	}
	buf := make([]byte, hex.EncodedLen(len(b))+2)
	buf[0] = '"'
	hex.Encode(buf[1:len(buf)-1], b)
	buf[len(buf)-1] = '"'
	return buf
}

func fromJSONHex(dst []byte, src []byte) error {
	if bytes.Equal(src, []byte(`""`)) {
		copy(dst, make([]byte, len(dst)))
		return nil
	}
	if len(src) != hex.EncodedLen(len(dst))+2 {
		return fmt.Errorf("wrong hex size: %v instead of %v", len(src), hex.EncodedLen(len(dst))+2)
	}
	if src[0] != '"' || src[len(src)-1] != '"' {
		return fmt.Errorf("wrong quotes %q/%q", src[0], src[len(src)-1])
	}
	_, err := hex.Decode(dst, src[1:len(src)-1])
	return err
}

func toBinary(b []byte) []byte {
	if emptyOrZero(b) {
		return nil
	}
	return b
}

func fromBinary(dst []byte, src []byte) error {
	if len(src) == 0 {
		return nil
	}
	if len(src) != len(dst) {
		return fmt.Errorf("wrong binary size: %v instead of %v", len(src), len(dst))
	}
	copy(dst, src)
	return nil
}

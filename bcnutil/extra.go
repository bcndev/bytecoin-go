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

package bcnutil

import (
	"bytes"
	"encoding/binary"
	"unicode"

	"github.com/bcndev/bytecoin-go"
)

const (
	extraTagPadding           = 0
	extraTagPublicKey         = 1
	extraTagExtraNonce        = 2
	extraTagMMTag             = 3
	extraTagBlockCapacityVote = 4
)

type ExtraFields struct {
	Padding           int
	PublicKey         *bytecoin.PublicKey
	PaymentId         *bytecoin.Hash
	ExtraNonce        bytecoin.HexBlob
	ExtraNonceText    string
	MMRoot            *bytecoin.Hash
	MMDepth           int
	BlockCapacityVote *uint64
	SplitExtra        []bytecoin.HexBlob
}

func ParseExtra(extra []byte) ExtraFields {
	var (
		fields    ExtraFields
		leftovers []int
		data      []byte
		tag       byte
		ok        bool
		size      uint64
	)

	r := bytes.NewReader(extra)
loop:
	for {
		tag, leftovers, ok = readExtraByte(r, leftovers)
		if !ok {
			break
		}

		switch tag {
		case extraTagPadding:
			fields.Padding = r.Len() + 1
			leftovers = append(leftovers, 0)
			break loop
		case extraTagPublicKey:
			data, leftovers, ok = readExtraBlob(r, leftovers, 32)
			if !ok {
				break loop
			}
			if fields.PublicKey == nil {
				fields.PublicKey = &bytecoin.PublicKey{}
				copy(fields.PublicKey[:], data)
			}
		case extraTagExtraNonce:
			size, leftovers, ok = readExtraVarint(r, leftovers)
			if !ok {
				break loop
			}
			data, leftovers, ok = readExtraBlob(r, leftovers, size)
			if !ok {
				break loop
			}

			if size == 32+1 && data[0] == 0 {
				if fields.PaymentId == nil {
					fields.PaymentId = &bytecoin.Hash{}
					copy(fields.PaymentId[:], data[1:])
				}
			} else {
				fields.ExtraNonce = data
				fields.ExtraNonceText = extraNonceText(data)
			}
		case extraTagMMTag:
			size, leftovers, ok = readExtraVarint(r, leftovers)
			if !ok {
				break loop
			}
			data, leftovers, ok = readExtraBlob(r, leftovers, size)
			if !ok {
				break loop
			}

			if size == 32+1 {
				if fields.MMRoot == nil {
					fields.MMDepth = int(data[0])
					fields.MMRoot = &bytecoin.Hash{}
					copy(fields.MMRoot[:], data[1:])
				}
			}
		case extraTagBlockCapacityVote:
			size, leftovers, ok = readExtraVarint(r, leftovers)
			if !ok {
				break loop
			}
			data, leftovers, ok = readExtraBlob(r, leftovers, size)
			if !ok {
				break loop
			}
			r2 := bytes.NewReader(data)
			cv, err := binary.ReadUvarint(r2)
			if err == nil { // && r2.Len() == 0 - TODO add after C++ code is updated after hardfork
				if fields.BlockCapacityVote == nil {
					fields.BlockCapacityVote = &cv
				}
			}
		default:
			size, leftovers, ok = readExtraVarint(r, leftovers)
			if !ok {
				break loop
			}
			_, leftovers, ok = readExtraBlob(r, leftovers, size)
			if !ok {
				break loop
			}
		}
	}

	prev := 0
	for i := 0; i < len(leftovers) && prev != len(extra); i++ {
		fields.SplitExtra = append(fields.SplitExtra, extra[prev:len(extra)-leftovers[i]])
		prev = len(extra) - leftovers[i]
	}

	return fields
}

func readExtraByte(r *bytes.Reader, leftovers []int) (byte, []int, bool) {
	b, err := r.ReadByte()
	return b, append(leftovers, r.Len()), err == nil
}

func readExtraVarint(r *bytes.Reader, leftovers []int) (uint64, []int, bool) {
	b, err := binary.ReadUvarint(r)
	return b, append(leftovers, r.Len()), err == nil
}

func readExtraBlob(r *bytes.Reader, leftovers []int, size uint64) ([]byte, []int, bool) {
	readSize := size
	if readSize > uint64(r.Len()) {
		readSize = uint64(r.Len())
	}
	buf := make([]byte, readSize)
	n, _ := r.Read(buf)
	return buf[:n], append(leftovers, r.Len()), uint64(n) == size
}

func extraNonceText(en []byte) string {
	text := &bytes.Buffer{}
	for _, ch := range string(en) {
		if unicode.IsPrint(ch) {
			text.WriteRune(ch)
		} else {
			text.WriteRune(unicode.ReplacementChar)
		}
	}
	return text.String()
}

func ExtraExtraNonce(extraNonce []byte) []byte {
	return append(append([]byte{extraTagExtraNonce}, getVarintData(uint64(len(extraNonce)))...), extraNonce...)
}

func ExtraMergeMiningTag(mmRoot bytecoin.Hash, mmDepth byte) []byte {
	blob := append(getVarintData(uint64(mmDepth)), mmRoot[:]...)

	return append(append([]byte{extraTagMMTag}, getVarintData(uint64(len(blob)))...), blob...)
}

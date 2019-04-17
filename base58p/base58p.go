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

package base58p

import (
	"errors"
	"fmt"
)

const (
	base         = 58
	chunksizeEnc = 8
	chunksizeDec = 11
	Alphabet     = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
)

var (
	chunksizesEnc = [chunksizeEnc + 1]int{0, 2, 3, 5, 6, 7, 9, 10, 11}
	chunksizesDec = [chunksizeDec + 1]int{0, -1, 1, 2, -1, 3, 4, 5, -1, 6, 7, 8}

	revAlphabet [255]int

	errOverflow = errors.New("base58p value overflow")
)

func init() {
	for i := range revAlphabet {
		revAlphabet[i] = -1
	}
	for i, b := range Alphabet {
		revAlphabet[b] = i
	}
}

func byteBits(i int) uint {
	return uint(i) * 8
}

func readBE(data []byte) uint64 {
	n := uint64(0)
	for i := len(data) - 1; i >= 0; i-- {
		j := len(data) - i - 1
		n |= uint64(data[i]) << byteBits(j)
	}
	return n
}

func writeBE(buf []byte, n uint64) {
	for i := len(buf) - 1; n > 0; i-- {
		buf[i] = byte(n & 0xff)
		n >>= byteBits(1)
	}
}

func EncodedLen(n int) int {
	var (
		div = n / chunksizeEnc
		mod = n % chunksizeEnc
	)
	return div*chunksizesEnc[chunksizeEnc] + chunksizesEnc[mod]
}

func DecodedLen(n int) int {
	var (
		div = n / chunksizeDec
		mod = n % chunksizeDec
		r   = chunksizesDec[mod]
	)
	if r < 0 {
		return -1
	}
	return div*chunksizesDec[chunksizeDec] + r
}

func Encode(dst []byte, src []byte) {
	k := 0
	for i := 0; i < len(src); i += chunksizeEnc {
		j := i + chunksizeEnc
		if j > len(src) {
			j = len(src)
		}

		ch1 := src[i:j]
		ch2 := dst[k : k+chunksizesEnc[len(ch1)]]

		n := readBE(ch1)
		for p := len(ch2) - 1; p >= 0; p-- {
			div := n / base
			mod := n % base

			ch2[p] = Alphabet[mod]

			n = div
		}

		k += len(ch2)
	}
}

func EncodeToString(src []byte) string {
	dst := make([]byte, EncodedLen(len(src)))
	Encode(dst, src)
	return string(dst)
}

func Decode(dst []byte, src []byte) (int, error) {
	s := DecodedLen(len(src))
	if s < 0 {
		return 0, fmt.Errorf("invalid size of base58p data: %d", len(src))
	}

	k := 0
	for i := 0; i < len(src); i += chunksizeDec {
		j := i + chunksizeDec
		if j > len(src) {
			j = len(src)
		}

		ch1 := src[i:j]
		ch2 := dst[k : k+chunksizesDec[len(ch1)]]

		n := uint64(0)
		m := uint64(1)
		max := uint64(1<<byteBits(len(ch2)) - 1)

		for p := len(ch1) - 1; p >= 0; p-- {
			x := revAlphabet[ch1[p]]
			if x < 0 {
				return k, fmt.Errorf("invalid character for base58p: %v", ch1[p])
			}

			if x != 0 && m > max/uint64(x) {
				return k, errOverflow
			}

			delta := uint64(x) * m

			n += delta
			if n < delta {
				return k, errOverflow
			}

			m *= base
		}
		if n > max {
			return k, errOverflow
		}
		writeBE(ch2, n)

		k += len(ch2)
	}

	return k, nil
}

func DecodeString(s string) ([]byte, error) {
	l := DecodedLen(len(s))
	if l < 0 {
		return nil, fmt.Errorf("invalid size of base58p data: %d", len(s))
	}

	dst := make([]byte, l)
	_, err := Decode(dst, []byte(s))
	if err != nil {
		return nil, err
	}

	return dst, nil
}

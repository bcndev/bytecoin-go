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
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	benchDec = "7Gcf6TszN3wAZnDEdxe8hSQX5iSkaGDdwM2etSchNqWH"
	benchEnc = "\x25\x7b\x31\x26\x36\xb9\x16\x26\x39\x2f\xb6\x74\x77\x59\x86\x1d\x8c\x9b\xd8\xe8\xc0\x4f\x36\x16\x77\xbe\x1b\x14\xff\xa2\xa4\xca"
)

var (
	base58size = map[int]int{
		0:  0,
		11: 8,
		12: -1,
		13: 9,
	}

	uint64be = map[uint64][]byte{
		0x0000000000000001: []byte("\x01"),
		0x0000000000000102: []byte("\x01\x02"),
		0x0000000000010203: []byte("\x01\x02\x03"),
		0x0000000001020304: []byte("\x01\x02\x03\x04"),
		0x0000000102030405: []byte("\x01\x02\x03\x04\x05"),
		0x0000010203040506: []byte("\x01\x02\x03\x04\x05\x06"),
		0x0001020304050607: []byte("\x01\x02\x03\x04\x05\x06\x07"),
		0x0102030405060708: []byte("\x01\x02\x03\x04\x05\x06\x07\x08"),
	}

	base58dec = map[string][]byte{
		"1z":                     []byte("\x39"),
		"5Q":                     []byte("\xFF"),
		"11z":                    []byte("\x00\x39"),
		"15R":                    []byte("\x01\x00"),
		"LUv":                    []byte("\xFF\xFF"),
		"1111z":                  []byte("\x00\x00\x39"),
		"11LUw":                  []byte("\x01\x00\x00"),
		"2UzHL":                  []byte("\xFF\xFF\xFF"),
		"11111z":                 []byte("\x00\x00\x00\x39"),
		"7YXq9G":                 []byte("\xFF\xFF\xFF\xFF"),
		"111111z":                []byte("\x00\x00\x00\x00\x39"),
		"VtB5VXc":                []byte("\xFF\xFF\xFF\xFF\xFF"),
		"11111111z":              []byte("\x00\x00\x00\x00\x00\x39"),
		"3CUsUpv9t":              []byte("\xFF\xFF\xFF\xFF\xFF\xFF"),
		"111111111z":             []byte("\x00\x00\x00\x00\x00\x00\x39"),
		"Ahg1opVcGW":             []byte("\xFF\xFF\xFF\xFF\xFF\xFF\xFF"),
		"1111111111z":            []byte("\x00\x00\x00\x00\x00\x00\x00\x39"),
		"jpXCZedGfVQ":            []byte("\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"),
		"11111111112":            []byte("\x00\x00\x00\x00\x00\x00\x00\x01"),
		"11111111119":            []byte("\x00\x00\x00\x00\x00\x00\x00\x08"),
		"1111111111A":            []byte("\x00\x00\x00\x00\x00\x00\x00\x09"),
		"11111111121":            []byte("\x00\x00\x00\x00\x00\x00\x00\x3A"),
		"1Ahg1opVcGW":            []byte("\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF"),
		"22222222222":            []byte("\x06\x15\x60\x13\x76\x28\x79\xF7"),
		"1z111111111":            []byte("\x05\xE0\x22\xBA\x37\x4B\x2A\x00"),
		"11":                     []byte("\x00"),
		"111":                    []byte("\x00\x00"),
		"11111":                  []byte("\x00\x00\x00"),
		"111111":                 []byte("\x00\x00\x00\x00"),
		"1111111":                []byte("\x00\x00\x00\x00\x00"),
		"111111111":              []byte("\x00\x00\x00\x00\x00\x00"),
		"1111111111":             []byte("\x00\x00\x00\x00\x00\x00\x00"),
		"11111111111":            []byte("\x00\x00\x00\x00\x00\x00\x00\x00"),
		"1111111111111":          []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
		"11111111111111":         []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
		"1111111111111111":       []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
		"11111111111111111":      []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
		"111111111111111111":     []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
		"11111111111111111111":   []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
		"111111111111111111111":  []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
		"1111111111111111111111": []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
		"22222222222VtB5VXc":     []byte("\x06\x15\x60\x13\x76\x28\x79\xF7\xFF\xFF\xFF\xFF\xFF"),
		"1":                      nil,
		"z":                      nil,
		"1111":                   nil,
		"zzzz":                   nil,
		"11111111":               nil,
		"zzzzzzzz":               nil,
		"123456789AB1":           nil,
		"123456789ABz":           nil,
		"123456789AB1111":        nil,
		"123456789ABzzzz":        nil,
		"123456789AB11111111":    nil,
		"123456789ABzzzzzzzz":    nil,
		"5R":                     nil,
		"zz":                     nil,
		"LUw":                    nil,
		"zzz":                    nil,
		"2UzHM":                  nil,
		"zzzzz":                  nil,
		"7YXq9H":                 nil,
		"zzzzzz":                 nil,
		"VtB5VXd":                nil,
		"zzzzzzz":                nil,
		"3CUsUpv9u":              nil,
		"zzzzzzzzz":              nil,
		"Ahg1opVcGX":             nil,
		"zzzzzzzzzz":             nil,
		"jpXCZedGfVR":            nil,
		"zzzzzzzzzzz":            nil,
		"123456789AB5R":          nil,
		"123456789ABzz":          nil,
		"123456789ABLUw":         nil,
		"123456789ABzzz":         nil,
		"123456789AB2UzHM":       nil,
		"123456789ABzzzzz":       nil,
		"123456789AB7YXq9H":      nil,
		"123456789ABzzzzzz":      nil,
		"123456789ABVtB5VXd":     nil,
		"123456789ABzzzzzzz":     nil,
		"123456789AB3CUsUpv9u":   nil,
		"123456789ABzzzzzzzzz":   nil,
		"123456789ABAhg1opVcGX":  nil,
		"123456789ABzzzzzzzzzz":  nil,
		"123456789ABjpXCZedGfVR": nil,
		"123456789ABzzzzzzzzzzz": nil,
		"zzzzzzzzzzz11":          nil,
		"10":                     nil,
		"11I":                    nil,
		"11O11":                  nil,
		"11l111":                 nil,
		"01111111111":            nil,
		"11111111110":            nil,
		"11111011111":            nil,
		"I1111111111":            nil,
		"O1111111111":            nil,
		"l1111111111":            nil,
		"_1111111111":            nil,
		"11_11111111":            nil,
		"1101111111111":          nil,
		"11I11111111111111":      nil,
		"11O1111111111111111111": nil,
		"1111111111110":          nil,
		"111111111111l1111":      nil,
		"111111111111_111111111": nil,
	}
)

func TestReadBE(t *testing.T) {
	for n, buf := range uint64be {
		have := readBE([]byte(buf))
		assert.Equalf(t, n, have, "wrong decoding for %x", buf)
	}
}

func TestWriteBE(t *testing.T) {
	for n, buf := range uint64be {
		out := make([]byte, len(buf))
		writeBE(out, n)
		assert.Equalf(t, []byte(buf), out, "wrong encoding for %d", n)
	}
}

func TestEncodedLen(t *testing.T) {
	for enc, dec := range base58size {
		if dec < 0 {
			continue
		}
		have := EncodedLen(dec)
		assert.Equalf(t, enc, have, "wrong len for %d", dec)
	}
}

func TestDecodedLen(t *testing.T) {
	for enc, dec := range base58size {
		have := DecodedLen(enc)
		assert.Equalf(t, dec, have, "wrong len for %d", enc)
	}
}

func TestEncodeToString(t *testing.T) {
	for enc, dec := range base58dec {
		if dec == nil {
			continue
		}
		have := EncodeToString(dec)
		assert.Equalf(t, enc, have, "wrong encoding of %x", dec)
	}
}

func TestDecodeString(t *testing.T) {
	for enc, dec := range base58dec {
		have, err := DecodeString(enc)
		if dec == nil {
			if assert.Nilf(t, have, "non-nil decoding for %s", enc) {
				assert.Errorf(t, err, "absence of decoding error for %s", enc)
			}
		} else {
			if assert.Equalf(t, dec, have, "wrong decoding of %s", enc) {
				assert.NoErrorf(t, err, "decoding error for %s", enc)
			}
		}
	}
}

func BenchmarkEncode(b *testing.B) {
	src := []byte(benchEnc)
	dst := make([]byte, EncodedLen(len(src)))
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		Encode(dst, src)
	}
}

func BenchmarkDecode(b *testing.B) {
	src := []byte(benchDec)
	dst := make([]byte, DecodedLen(len(benchDec)))
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		Decode(dst, src)
	}
}

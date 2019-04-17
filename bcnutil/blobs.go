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
	"fmt"

	"github.com/bcndev/bytecoin-go"
)

func AuxBlockHeaderHash(tmpl bytecoin.BinBlockTemplate) (hash bytecoin.Hash, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("failed to calc aux block header hash: %v", r)
		}
	}()

	var b bytes.Buffer
	serBlockTemplateHeader(&tmpl, rw{nil, &b}, kindPreHash, bodyProxyFromTemplate(tmpl))

	return FastHash(getVarintData(uint64(b.Len())), b.Bytes()), nil
}

func BlockHash(tmpl bytecoin.BinBlockTemplate) (hash bytecoin.Hash, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("failed to calc block hash: %v", r)
		}
	}()

	var b bytes.Buffer
	serBlockTemplateHeader(&tmpl, rw{nil, &b}, kindBlockHash, bodyProxyFromTemplate(tmpl))

	return FastHash(getVarintData(uint64(b.Len())), b.Bytes()), nil
}

func BlockLongHashingData(tmpl bytecoin.BinBlockTemplate) (data []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("failed to calc block long hashing data: %v", r)
		}
	}()

	var b bytes.Buffer
	serBlockTemplateHeader(&tmpl, rw{nil, &b}, kindLongBlockHash, bodyProxyFromTemplate(tmpl))

	return b.Bytes(), nil
}

func MarshalMMBlockTemplate(tmpl bytecoin.BinBlockTemplate) (data []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("failed to marshal merge mining block template: %v", r)
		}
	}()

	var b bytes.Buffer
	serBlockTemplate(&tmpl, rw{nil, &b}, kindNormal, BinBlockBodyProxy{})

	return b.Bytes(), nil
}

func UnmarshalMMBlockTemplate(blob []byte) (tmpl bytecoin.BinBlockTemplate, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("failed to unmarshal merge mining block template: %v", r)
		}
	}()

	serBlockTemplate(&tmpl, rw{bytes.NewReader(blob), nil}, kindNormal, BinBlockBodyProxy{})

	return tmpl, nil
}

type BinBlockBodyProxy struct {
	TransactionsMerkleRoot bytecoin.Hash
	TransactionCount       int
}

func bodyProxyFromTemplate(tmpl bytecoin.BinBlockTemplate) BinBlockBodyProxy {
	hashes := append([]bytecoin.Hash{getTransactionHash(tmpl.CoinbaseTransaction)}, tmpl.TransactionHashes...)

	return BinBlockBodyProxy{
		TransactionsMerkleRoot: TreeHash(hashes),
		TransactionCount:       len(hashes),
	}
}

func getRootBlockBaseTransactionHash(prefix bytecoin.BinTransactionPrefix) bytecoin.Hash {
	var b bytes.Buffer

	if prefix.Version < 2 {
		serBaseTransaction(&prefix, rw{nil, &b})
		return FastHash(b.Bytes())
	} else {
		serTransactionPrefix(&prefix, rw{nil, &b})

		// XMR(XMO) as popular MM root, see details in monero/src/cryptonote_basic/cryptonote_format_utils.cpp
		// bc36789e7a1e281436464229828f817d6612f7b477d66591ff96a9e064bcc98a = hash(1 zero byte (RCTTypeNull))
		xmoRoot := []byte{
			0xbc, 0x36, 0x78, 0x9e, 0x7a, 0x1e, 0x28, 0x14, 0x36, 0x46, 0x42, 0x29, 0x82, 0x8f, 0x81, 0x7d,
			0x66, 0x12, 0xf7, 0xb4, 0x77, 0xd6, 0x65, 0x91, 0xff, 0x96, 0xa9, 0xe0, 0x64, 0xbc, 0xc9, 0x8a,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

		return FastHash(b.Bytes(), xmoRoot)
	}
}

func getTransactionPrefixHash(prefix bytecoin.BinTransactionPrefix) bytecoin.Hash {
	var b bytes.Buffer

	serTransactionPrefix(&prefix, rw{nil, &b})

	return FastHash(b.Bytes())
}

func getTransactionHash(tx bytecoin.BinTransaction) bytecoin.Hash {
	pr := getTransactionPrefixHash(tx.BinTransactionPrefix)
	if tx.Version < 4 {
		return pr
	}
	// Amethyst
	sh := FastHash([]byte{}) // coinbase has empty sigs

	return FastHash(pr[:], sh[:])
}

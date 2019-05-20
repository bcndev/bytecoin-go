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

type Format int

const (
	FormatBytecoin    = Format(0)
	FormatElectroneum = Format(1)
)

func BlockHeaderPreHash(tmpl bytecoin.BinBlockTemplate) (hash bytecoin.Hash, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("failed to calc block header prehash: %v", r)
		}
	}()

	var b bytes.Buffer
	serBlockTemplateHeader(&tmpl, rw{nil, &b}, FormatBytecoin, kindPreHash, bodyProxyFromTemplate(tmpl, FormatBytecoin))

	return FastHash(getVarintData(uint64(b.Len())), b.Bytes()), nil
}

func BlockHash(tmpl bytecoin.BinBlockTemplate, format Format) (hash bytecoin.Hash, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("failed to calc block hash: %v", r)
		}
	}()

	var b bytes.Buffer
	serBlockTemplateHeader(&tmpl, rw{nil, &b}, format, kindBlockHash, bodyProxyFromTemplate(tmpl, format))

	return FastHash(getVarintData(uint64(b.Len())), b.Bytes()), nil
}

func BlockPoWHashingData(tmpl bytecoin.BinBlockTemplate, format Format) (data []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("failed to calc block PoW hashing data: %v", r)
		}
	}()

	var b bytes.Buffer
	serBlockTemplateHeader(&tmpl, rw{nil, &b}, format, kindPoWBlockHash, bodyProxyFromTemplate(tmpl, format))

	return b.Bytes(), nil
}

func BlockTemplateToRootBlock(tmpl bytecoin.BinBlockTemplate, format Format) bytecoin.BinRootBlock {
	hashes := append([]bytecoin.Hash{getCoinbaseTransactionHash(tmpl.CoinbaseTransaction.BinTransactionPrefix, format)}, tmpl.TransactionHashes...)

	return bytecoin.BinRootBlock{
		MajorVersion:              tmpl.MajorVersion,
		MinorVersion:              tmpl.MinorVersion,
		Nonce:                     append(bytecoin.HexBlob(nil), tmpl.Nonce...),
		Timestamp:                 tmpl.Timestamp,
		PreviousBlockHash:         tmpl.PreviousBlockHash,
		TransactionCount:          len(hashes),
		CoinbaseTransactionBranch: CoinbaseTreeBranch(hashes),
		CoinbaseTransaction:       tmpl.CoinbaseTransaction.BinTransactionPrefix,
	}
}

func BinRootBlockPoWHashingData(root bytecoin.BinRootBlock) (data []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("failed to calc root block PoW hashing data: %v", r)
		}
	}()

	var b bytes.Buffer
	serRootBlock(&root, rw{nil, &b}, kindPoWBlockHash)

	return b.Bytes(), nil
}

func MarshalBlockTemplate(tmpl bytecoin.BinBlockTemplate, format Format) (data []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("failed to marshal block template: %v", r)
		}
	}()

	var b bytes.Buffer
	serBlockTemplate(&tmpl, rw{nil, &b}, format, kindNormal, BinBlockBodyProxy{})

	return b.Bytes(), nil
}

func UnmarshalBlockTemplate(blob []byte, format Format) (tmpl bytecoin.BinBlockTemplate, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("failed to unmarshal block template: %v", r)
		}
	}()

	serBlockTemplate(&tmpl, rw{bytes.NewReader(blob), nil}, format, kindNormal, BinBlockBodyProxy{})

	return tmpl, nil
}

type BinBlockBodyProxy struct {
	TransactionsMerkleRoot bytecoin.Hash
	TransactionCount       int
}

func bodyProxyFromTemplate(tmpl bytecoin.BinBlockTemplate, format Format) BinBlockBodyProxy {
	hashes := append([]bytecoin.Hash{getCoinbaseTransactionHash(tmpl.CoinbaseTransaction.BinTransactionPrefix, format)}, tmpl.TransactionHashes...)

	return BinBlockBodyProxy{
		TransactionsMerkleRoot: TreeHash(hashes),
		TransactionCount:       len(hashes),
	}
}

func getTransactionPrefixHash(prefix bytecoin.BinTransactionPrefix) bytecoin.Hash {
	var b bytes.Buffer

	serTransactionPrefix(&prefix, rw{nil, &b})

	return FastHash(b.Bytes())
}

func getCoinbaseTransactionHash(prefix bytecoin.BinTransactionPrefix, format Format) bytecoin.Hash {
	switch format {
	case FormatBytecoin:
		return getBCNCoinbaseTransactionHash(prefix)
	case FormatElectroneum:
		return getETNCoinbaseTransactionHash(prefix)
	default:
		panic(fmt.Sprintf("invalid serialization format %#v", format))
	}
}

func getBCNCoinbaseTransactionHash(prefix bytecoin.BinTransactionPrefix) bytecoin.Hash {
	h := getTransactionPrefixHash(prefix)
	if prefix.Version < 4 {
		return h
	}

	// Amethyst
	extra := FastHash() // coinbase has no signatures

	return FastHash(h[:], extra[:])
}

func getETNCoinbaseTransactionHash(prefix bytecoin.BinTransactionPrefix) bytecoin.Hash {
	h := getTransactionPrefixHash(prefix)
	if prefix.Version < 2 {
		return h
	}

	// XMR(XMO) as popular MM root, see details in monero/src/cryptonote_basic/cryptonote_format_utils.cpp
	// bc36789e7a1e281436464229828f817d6612f7b477d66591ff96a9e064bcc98a = hash(1 zero byte (RCTTypeNull))
	extra := []byte{
		0xbc, 0x36, 0x78, 0x9e, 0x7a, 0x1e, 0x28, 0x14, 0x36, 0x46, 0x42, 0x29, 0x82, 0x8f, 0x81, 0x7d,
		0x66, 0x12, 0xf7, 0xb4, 0x77, 0xd6, 0x65, 0x91, 0xff, 0x96, 0xa9, 0xe0, 0x64, 0xbc, 0xc9, 0x8a,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	return FastHash(h[:], extra)
}

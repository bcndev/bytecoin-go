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
	"encoding/binary"
	"io"

	"github.com/bcndev/bytecoin-go"
)

const (
	kindNormal       = 0
	kindPreHash      = 1
	kindBlockHash    = 2
	kindPoWBlockHash = 3

	typeTagOutputKey     = 2
	typeTagInputKey      = 2
	typeTagInputCoinbase = 255
)

func getVarintData(v uint64) []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(buf, v)
	return buf[:n]
}

type rw struct {
	r io.ByteReader
	w io.ByteWriter
}

func (rw rw) VarintUint64(v *uint64) {
	var err error
	if rw.r != nil {
		*v, err = binary.ReadUvarint(rw.r)
		if err != nil {
			panic("read_varint failed")
		}
	} else {
		buf := getVarintData(*v)
		for i := 0; i < len(buf); i += 1 {
			err = rw.w.WriteByte(buf[i])
			if err != nil {
				panic("read_varint failed")
			}
		}
	}
}

func (rw rw) Varint(v *int) {
	if rw.r != nil {
		vv := uint64(0)
		rw.VarintUint64(&vv)
		*v = int(vv) // TODO - checked conversion
	} else {
		vv := uint64(*v) // TODO - checked conversion
		rw.VarintUint64(&vv)
	}
}

func (rw rw) VarintUint32(v *uint32) {
	if rw.r != nil {
		vv := uint64(0)
		rw.VarintUint64(&vv)
		*v = uint32(vv) // TODO - checked conversion
	} else {
		vv := uint64(*v) // TODO - checked conversion
		rw.VarintUint64(&vv)
	}
}

func (rw rw) Binary(v []byte, n int) {
	if len(v) != n {
		panic("read/write_binary failed (wrong len)")
	}
	if rw.r != nil {
		for i := 0; i < n; i += 1 {
			b, err := rw.r.ReadByte()
			if err != nil {
				panic("read_binary failed")
			}
			v[i] = b
		}
	} else {
		for i := 0; i < n; i += 1 {
			err := rw.w.WriteByte(v[i])
			if err != nil {
				panic("write_binary failed")
			}
		}
	}
}

func serTransactionInput(v *bytecoin.BinTransactionInput, rw rw) {
	if rw.r != nil {
		b, err := rw.r.ReadByte()
		if err != nil {
			panic("serTransactionInput ReadByte failed")
		}
		if b == typeTagInputKey {
			rw.VarintUint64(&v.Amount)
			mixinCount := 0
			rw.Varint(&mixinCount)
			v.OutputIndexes = make([]int, mixinCount)
			for ind := range v.OutputIndexes {
				rw.Varint(&v.OutputIndexes[ind])
			}
			rw.Binary(v.KeyImage[:], 32)
			v.Type = "key"
		} else if b == typeTagInputCoinbase {
			rw.Varint(&v.Height)
			v.Type = "coinbase"
		} else {
			panic("Unknown input type")
		}
	} else {
		if v.Type == "key" {
			err := rw.w.WriteByte(typeTagInputKey)
			if err != nil {
				panic("serTransactionInput WriteByte failed")
			}
			rw.VarintUint64(&v.Amount)
			mixinCount := len(v.OutputIndexes)
			rw.Varint(&mixinCount)
			for ind := range v.OutputIndexes {
				rw.Varint(&v.OutputIndexes[ind])
			}
			rw.Binary(v.KeyImage[:], 32)
		} else if v.Type == "coinbase" {
			err := rw.w.WriteByte(typeTagInputCoinbase)
			if err != nil {
				panic("serTransactionInput WriteByte failed")
			}
			rw.Varint(&v.Height)
		} else {
			panic("Unknown input type")
		}
	}
}

func serTransactionOutput(v *bytecoin.BinTransactionOutput, rw rw, isAmethyst bool) {
	if !isAmethyst {
		rw.VarintUint64(&v.Amount)
	}
	if rw.r != nil {
		b, err := rw.r.ReadByte()
		if err != nil {
			panic("serTransactionOutput ReadByte failed")
		}
		if b != typeTagOutputKey {
			panic("Unknown output type")
		}
		v.Type = "key"
	} else {
		if v.Type != "key" {
			panic("Unknown output type")
		}
		err := rw.w.WriteByte(typeTagOutputKey)
		if err != nil {
			panic("serTransactionOutput WriteByte failed")
		}
	}
	if isAmethyst {
		rw.VarintUint64(&v.Amount)
	}
	rw.Binary(v.PublicKey[:], 32)
	if isAmethyst {
		if v.EncryptedSecret == nil {
			v.EncryptedSecret = &bytecoin.PublicKey{}
		}
		rw.Binary(v.EncryptedSecret[:], 32)
		if rw.r != nil {
			b, err := rw.r.ReadByte()
			if err != nil {
				panic("serTransactionOutput ReadByte failed")
			}
			v.EncryptedAddressType = bytecoin.HexBlob{b}
		} else {
			if len(v.EncryptedAddressType) != 1 {
				panic("serTransactionOutput EncryptedAddressType must be exactly 1 byte")
			}
			err := rw.w.WriteByte(v.EncryptedAddressType[0])
			if err != nil {
				panic("serTransactionOutput WriteByte failed")
			}
		}
	}
}

func serTransactionPrefix(v *bytecoin.BinTransactionPrefix, rw rw) {
	rw.Varint(&v.Version)
	rw.VarintUint64(&v.UnlockTime)
	if rw.r != nil {
		inputsCount := 0
		rw.Varint(&inputsCount)
		v.Inputs = make([]bytecoin.BinTransactionInput, inputsCount)
		for ind := range v.Inputs {
			serTransactionInput(&v.Inputs[ind], rw)
		}
		outputsCount := 0
		rw.Varint(&outputsCount)
		v.Outputs = make([]bytecoin.BinTransactionOutput, outputsCount)
		for ind := range v.Outputs {
			serTransactionOutput(&v.Outputs[ind], rw, v.Version >= 4)
		}
		extraLength := 0
		rw.Varint(&extraLength)
		v.Extra = make([]byte, extraLength)
		rw.Binary(v.Extra, extraLength)
	} else {
		inputsCount := len(v.Inputs)
		rw.Varint(&inputsCount)
		for ind := range v.Inputs {
			serTransactionInput(&v.Inputs[ind], rw)
		}
		outputsCount := len(v.Outputs)
		rw.Varint(&outputsCount)
		for ind := range v.Outputs {
			serTransactionOutput(&v.Outputs[ind], rw, v.Version >= 4)
		}
		extraLength := len(v.Extra)
		rw.Varint(&extraLength)
		rw.Binary(v.Extra, extraLength)
	}
}

func serBaseTransaction(v *bytecoin.BinTransactionPrefix, rw rw) {
	serTransactionPrefix(v, rw)
	if v.Version >= 2 {
		ignored := 0
		rw.Varint(&ignored)
	}
}

func serRootBlock(v *bytecoin.BinRootBlock, rw rw, kind int) {
	rw.Varint(&v.MajorVersion)
	rw.Varint(&v.MinorVersion)
	rw.VarintUint32(&v.Timestamp)
	rw.Binary(v.PreviousBlockHash[:], 32)
	if v.Nonce == nil {
		v.Nonce = make([]byte, 4)
	}
	rw.Binary(v.Nonce, 4)
	if kind == kindBlockHash || kind == kindPoWBlockHash {
		minerTxHash := getETNCoinbaseTransactionHash(v.CoinbaseTransaction)
		merkleRoot := TreeHashFromBranch(v.CoinbaseTransactionBranch, len(v.CoinbaseTransactionBranch), minerTxHash, bytecoin.Hash{})
		rw.Binary(merkleRoot[:], 32)
	}
	rw.Varint(&v.TransactionCount)
	if v.TransactionCount < 1 {
		panic("Wrong transactions number")
	}
	if kind == kindPoWBlockHash {
		return
	}
	branchSize := CoinbaseTreeDepth(v.TransactionCount)
	if rw.r != nil {
		v.CoinbaseTransactionBranch = make([]bytecoin.Hash, branchSize)
	} else {
		if len(v.CoinbaseTransactionBranch) != branchSize {
			panic("Wrong miner transaction branch size")
		}
	}
	for ind := range v.CoinbaseTransactionBranch {
		rw.Binary(v.CoinbaseTransactionBranch[ind][:], 32)
	}
	serBaseTransaction(&v.CoinbaseTransaction, rw)

	extraFields := ParseExtra(v.CoinbaseTransaction.Extra)
	if extraFields.MMDepth > 256 {
		panic("Wrong merge mining tag depth")
	}
	if rw.r != nil {
		v.BlockChainBranch = make([]bytecoin.Hash, extraFields.MMDepth)
	} else {
		if len(v.BlockChainBranch) != extraFields.MMDepth {
			panic("Blockchain branch size must be equal to merge mining tag depth")
		}
	}
	for ind := range v.BlockChainBranch {
		rw.Binary(v.BlockChainBranch[ind][:], 32)
	}
}

func serBlockBodyProxy(v *BinBlockBodyProxy, rw rw) {
	rw.Binary(v.TransactionsMerkleRoot[:], 32)
	rw.Varint(&v.TransactionCount)
}

func serBlockTemplateHeader(v *bytecoin.BinBlockTemplate, rw rw, format Format, kind int, proxy BinBlockBodyProxy) {
	if kind == kindNormal {
		rw.Varint(&v.MajorVersion)
		rw.Varint(&v.MinorVersion)
		if v.MajorVersion == 1 || (format == FormatElectroneum && v.MajorVersion == 7) {
			rw.VarintUint32(&v.Timestamp)
			rw.Binary(v.PreviousBlockHash[:], 32)
			if v.Nonce == nil {
				v.Nonce = make([]byte, 4)
			}
			rw.Binary(v.Nonce, 4)
			return
		}
		if v.MajorVersion >= 2 && v.MajorVersion <= 4 { // MM
			rw.Binary(v.PreviousBlockHash[:], 32)
			serRootBlock(&v.RootBlock, rw, kind)
			return
		}
		// TODO - CM here
		panic("Unknown block major version")
	}
	if v.MajorVersion == 1 || (format == FormatElectroneum && v.MajorVersion == 7) {
		rw.Varint(&v.MajorVersion)
		rw.Varint(&v.MinorVersion)
		rw.VarintUint32(&v.Timestamp)
		rw.Binary(v.PreviousBlockHash[:], 32)
		if v.Nonce == nil {
			v.Nonce = make([]byte, 4)
		}
		rw.Binary(v.Nonce, 4)
		serBlockBodyProxy(&proxy, rw)
		return
	}
	if v.MajorVersion >= 2 && v.MajorVersion <= 4 { // MM
		if kind == kindPoWBlockHash {
			serRootBlock(&v.RootBlock, rw, kind)
			return
		}
		rw.Varint(&v.MajorVersion)
		rw.Varint(&v.MinorVersion)
		rw.Binary(v.PreviousBlockHash[:], 32)
		serBlockBodyProxy(&proxy, rw)
		if kind != kindPreHash {
			serRootBlock(&v.RootBlock, rw, kind)
		}
		return
	}
	// TODO - CM here
	panic("Unknown block major version")
}

func serBlockTemplate(v *bytecoin.BinBlockTemplate, rw rw, format Format, kind int, proxy BinBlockBodyProxy) {
	serBlockTemplateHeader(v, rw, format, kind, proxy)
	serTransactionPrefix(&v.CoinbaseTransaction.BinTransactionPrefix, rw)
	if rw.r != nil {
		count := 0
		rw.Varint(&count)
		v.TransactionHashes = make([]bytecoin.Hash, count)
		for ind := range v.TransactionHashes {
			rw.Binary(v.TransactionHashes[ind][:], 32)
		}
	} else {
		count := len(v.TransactionHashes)
		rw.Varint(&count)
		for ind := range v.TransactionHashes {
			rw.Binary(v.TransactionHashes[ind][:], 32)
		}
	}
}

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
	"golang.org/x/crypto/sha3"

	"github.com/bcndev/bytecoin-go"
)

func FastHash(blobs ...[]byte) bytecoin.Hash {
	k := sha3.NewLegacyKeccak256()
	for _, blob := range blobs {
		k.Write(blob)
	}

	var h bytecoin.Hash
	k.Sum(h[:0])
	return h
}

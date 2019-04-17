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
	"github.com/bcndev/bytecoin-go"
)

func TreeHash(hashes []bytecoin.Hash) bytecoin.Hash {
	count := len(hashes)

	switch count {
	case 0:
		return bytecoin.Hash{}
	case 1:
		return hashes[0]
	case 2:
		return FastHash(hashes[0][:], hashes[1][:])
	}

	cnt := 1
	for cnt*2 < count {
		cnt *= 2
	}

	tmp := make([]bytecoin.Hash, cnt)
	copy(tmp[:], hashes[:2*cnt-count])

	for i, j := 2*cnt-count, 2*cnt-count; j < cnt; i, j = i+2, j+1 {
		tmp[j] = FastHash(hashes[i][:], hashes[i+1][:])
	}

	for cnt > 2 {
		cnt /= 2
		for j := 0; j < cnt; j++ {
			tmp[j] = FastHash(tmp[2*j][:], tmp[2*j+1][:])
		}
	}

	return FastHash(tmp[0][:], tmp[1][:])
}

func CoinbaseTreeDepth(count int) int {
	depth := 0
	for uint64(1)<<uint(depth+1) <= uint64(count) {
		depth++
	}
	return depth
}

func CoinbaseTreeBranch(hashes []bytecoin.Hash) []bytecoin.Hash {
	count := len(hashes)
	depth := CoinbaseTreeDepth(count)
	cnt := 1 << uint(depth)

	tmp := make([]bytecoin.Hash, cnt-1)
	copy(tmp[:], hashes[1:2*cnt-count])

	for i, j := 2*cnt-count, 2*cnt-count-1; j < cnt-1; i, j = i+2, j+1 {
		tmp[j] = FastHash(hashes[i][:], hashes[i+1][:])
	}

	branch := make([]bytecoin.Hash, depth)
	for depth > 0 {
		cnt >>= 1
		depth--
		branch[depth] = tmp[0]

		for i, j := 1, 0; j < cnt-1; i, j = i+2, j+1 {
			tmp[j] = FastHash(tmp[i][:], tmp[i+1][:])
		}
	}

	return branch
}

func TreeHashFromBranch(branch []bytecoin.Hash, depth int, leaf bytecoin.Hash, path bytecoin.Hash) bytecoin.Hash {
	if depth == 0 {
		return leaf
	}

	buf := [2]bytecoin.Hash{}
	fromLeaf := true
	for depth > 0 {
		var leafPath, branchPath *bytecoin.Hash

		depth--
		if !path.IsZero() && ltrIndex(path, depth) != 0 {
			leafPath = &buf[1]
			branchPath = &buf[0]
		} else {
			leafPath = &buf[0]
			branchPath = &buf[1]
		}

		if fromLeaf {
			*leafPath = leaf
			fromLeaf = false
		} else {
			*leafPath = FastHash(buf[0][:], buf[1][:])
		}

		*branchPath = branch[depth]
	}

	return FastHash(buf[0][:], buf[1][:])
}

type MergeMiningItem struct {
	Leaf   bytecoin.Hash
	Path   bytecoin.Hash
	Branch []bytecoin.Hash
}

func FillMergeMiningBranches(items []MergeMiningItem) bytecoin.Hash {
	maxDepth := mergeMiningDepth(items, 0)

	var pItems []*MergeMiningItem
	for i := range items {
		pItems = append(pItems, &items[i])
	}

	h := doFillMergeMiningBranches(pItems, 0, maxDepth)

	for _, item := range pItems {
		for i, j := 0, len(item.Branch)-1; i < j; i, j = i+1, j-1 {
			item.Branch[i], item.Branch[j] = item.Branch[j], item.Branch[i]
		}
	}

	return h
}

func mergeMiningDepth(items []MergeMiningItem, depth int) int {
	if len(items) <= 1 {
		return depth
	}

	halves := [2][]MergeMiningItem{}
	for _, item := range items {
		i := ltrIndex(item.Path, depth)
		halves[i] = append(halves[i], item)
	}

	left := mergeMiningDepth(halves[0], depth+1)
	right := mergeMiningDepth(halves[1], depth+1)

	if left > right {
		return left
	} else {
		return right
	}
}

func doFillMergeMiningBranches(items []*MergeMiningItem, depth int, maxDepth int) bytecoin.Hash {
	if len(items) == 0 {
		return bytecoin.Hash{}
	}
	if depth == maxDepth {
		return items[0].Leaf
	}

	halves := [2][]*MergeMiningItem{}
	for _, item := range items {
		i := ltrIndex(item.Path, depth)
		halves[i] = append(halves[i], item)
	}

	hashes := [2]bytecoin.Hash{
		doFillMergeMiningBranches(halves[0], depth+1, maxDepth),
		doFillMergeMiningBranches(halves[1], depth+1, maxDepth),
	}

	for _, item := range items {
		i := ltrIndex(item.Path, depth)
		item.Branch = append(item.Branch, hashes[1-i])
	}

	return FastHash(hashes[0][:], hashes[1][:])
}

func ltrIndex(h bytecoin.Hash, depth int) int {
	if h[depth>>3]&(1<<uint(depth&7)) != 0 {
		return 1
	}

	return 0
}

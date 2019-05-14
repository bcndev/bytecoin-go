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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVerifyAddress(t *testing.T) {
	addrs := map[uint64]string{
		6:      "22bEHEYaiQAT2cRV9z7xdyRd4PQdaw9oDSukB6mx675hQq4G5J5SceLCpVnMxN6yH1E7auveLRWwjA5Bv7HCNnGGCLFrouY",
		572238: "bcnZEpbqJiChozdP5hQAFnBkeAvjdfUBhPw1vhE96CfQZaKKYfKSbdTKM7EN431ff95wRnBjeZbrpPo6aBBgRdYd2NkrEzEefr",
		18018:  "etnjxNhP2BVSuxzVyiLdNoU5yG3FoF8AmW4xAkcZfM2hfR5G7Q8B1oz5JrwV6FjQhx7s1dTctXQ3yhiAiEg1EJSJ4b6bXwJFVn",
	}

	for tag, addr := range addrs {
		assert.NoError(t, VerifyAddress(addr, tag))
	}
}

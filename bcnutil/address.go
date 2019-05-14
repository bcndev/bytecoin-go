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
	"fmt"

	"github.com/bcndev/bytecoin-go/base58p"
)

const (
	addrChecksumSize = 4
)

var (
	bcnTags = []uint64{6, 572238}
)

func VerifyAddress(addr string, tags ...uint64) error {
	data, err := base58p.DecodeString(addr)
	if err != nil {
		return err
	}

	tag, n := binary.Uvarint(data)
	if n <= 0 {
		return fmt.Errorf("failed to decode address tag")
	}

	if len(tags) == 0 {
		tags = bcnTags
	}
	tagFound := false
	for _, t := range tags {
		if t == tag {
			tagFound = true
			break
		}
	}
	if !tagFound {
		return fmt.Errorf("invalid address tag %v", tag)
	}

	if len(data) <= n+addrChecksumSize {
		return fmt.Errorf("address too short")
	}

	cs := FastHash(data[:len(data)-addrChecksumSize])
	if !bytes.Equal(cs[:addrChecksumSize], data[len(data)-addrChecksumSize:]) {
		return fmt.Errorf("invalid address checksum")
	}

	return nil
}

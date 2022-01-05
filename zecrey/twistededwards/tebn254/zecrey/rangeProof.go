/*
 * Copyright © 2021 Zecrey Protocol
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package zecrey

import (
	"log"
	"math/big"
	"github.com/zecrey-labs/zecrey-crypto/rangeProofs/twistededwards/tebn254/ctrange"
)

func proveCtRange(b int64, g, h *Point) (r *big.Int, proof *RangeProof, err error) {
	r, proof, err = ctrange.Prove(b, g, h)
	if err != nil {
		log.Println("[proveCtRange] err info:", err)
		return nil, nil, err
	}
	return r, proof, nil
}

func proveCtRangeRoutine(b int64, g, h *Point, r *big.Int, proof *RangeProof, rangeChan chan int) {
	var (
		err error
	)
	bar_r, rangeProof, err := ctrange.Prove(b, g, h)
	if err != nil {
		log.Println("[proveCtRangeRoutine] err info:", err)
		rangeChan <- ErrCode
		return
	}
	*proof = *rangeProof
	*r = *bar_r
	rangeChan <- 1
}

func verifyCtRangeRoutine(proof *RangeProof, rangeChan chan int) {
	res, err := proof.Verify()
	if err != nil {
		rangeChan <- ErrCode
		return
	}
	if !res {
		rangeChan <- ErrCode
		return
	}
	rangeChan <- 1
}

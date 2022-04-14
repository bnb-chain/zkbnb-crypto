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

package transactions

import "errors"

func SetFixedMerkleProofsAccountAsset(val [][]byte) (res [17][]byte, err error) {
	size := 17
	if len(val) != size {
		return res, errors.New("[SetFixedMerkleProofsAccountAsset] invalid size")
	}
	for i := 0; i < size; i++ {
		copy(res[i], val[i])
	}
	return res, nil
}

func SetFixedMerkleProofsHelperAccountAsset(val []int) (res [16]int, err error) {
	size := 16
	if len(val) != size {
		return res, errors.New("[SetFixedMerkleProofsAccountAsset] invalid size")
	}
	for i := 0; i < size; i++ {
		res[i] = val[i]
	}
	return res, nil
}

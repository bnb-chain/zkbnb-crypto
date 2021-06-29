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

import (
	"zecrey-crypto/zecrey/circuit/bn254/std"
	"zecrey-crypto/zecrey/twistededwards/tebn254/zecrey"
)

type AccountConstraints struct {
	Index   Variable // index in the tree
	TokenId Variable // tokenId
	Balance ElGamalEncConstraints
	PubKey  Point
}

// TODO only for test
type Account struct {
	Index   uint32
	TokenId uint32
	Balance *zecrey.ElGamalEnc
	PubKey  *zecrey.Point
}

func SetAccountWitness(account *Account) (witness AccountConstraints, err error) {
	witness.Index.Assign(int(account.Index))
	witness.TokenId.Assign(int(account.TokenId))
	witness.Balance, err = std.SetElGamalEncWitness(account.Balance)
	if err != nil {
		return witness, err
	}
	witness.PubKey, err = std.SetPointWitness(account.PubKey)
	if err != nil {
		return witness, err
	}
	return witness, nil
}

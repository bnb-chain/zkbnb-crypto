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
	"encoding/binary"
	"hash"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
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

func serializeAccount(account *Account) [160]byte {
	var res [160]byte
	binary.BigEndian.PutUint32(res[:32], account.Index)
	binary.BigEndian.PutUint32(res[32:64], account.TokenId)
	copy(res[64:96], account.Balance.CL.Marshal())
	copy(res[96:128], account.Balance.CR.Marshal())
	copy(res[128:160], account.PubKey.Marshal())
	return res
}

func deserializeAccount(accBytes [160]byte) *Account {
	index := binary.BigEndian.Uint32(accBytes[:32])
	tokenId := binary.BigEndian.Uint32(accBytes[32:64])
	CL, _ := curve.FromBytes(accBytes[64:96])
	CR, _ := curve.FromBytes(accBytes[96:128])
	PubKey, _ := curve.FromBytes(accBytes[128:160])
	return &Account{
		Index:   index,
		TokenId: tokenId,
		Balance: &zecrey.ElGamalEnc{
			CL: CL,
			CR: CR,
		},
		PubKey: PubKey,
	}
}

func mockAccountHash(account *Account, h hash.Hash) []byte {
	h.Reset()
	res := serializeAccount(account)
	h.Write(res[:])
	return h.Sum([]byte{})
}

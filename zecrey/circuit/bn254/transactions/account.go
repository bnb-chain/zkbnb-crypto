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
	AssetId Variable // tokenId
	Balance ElGamalEncConstraints
	PubKey  Point
}

// TODO only for test
type Account struct {
	Index   uint32
	AssetId uint32
	Balance *zecrey.ElGamalEnc
	PubKey  *zecrey.Point
}

func SetAccountWitness(account *Account) (witness AccountConstraints, err error) {
	witness.Index.Assign(int(account.Index))
	witness.AssetId.Assign(int(account.AssetId))
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

func SerializeAccount(account *Account) [AccountSize]byte {
	var res [AccountSize]byte
	binary.BigEndian.PutUint32(res[:PointSize], account.Index)
	binary.BigEndian.PutUint32(res[PointSize:2*PointSize], account.AssetId)
	copy(res[2*PointSize:3*PointSize], account.Balance.CL.Marshal())
	copy(res[3*PointSize:4*PointSize], account.Balance.CR.Marshal())
	copy(res[4*PointSize:5*PointSize], account.PubKey.Marshal())
	return res
}

func DeserializeAccount(accBytes [AccountSize]byte) *Account {
	index := binary.BigEndian.Uint32(accBytes[:PointSize])
	tokenId := binary.BigEndian.Uint32(accBytes[PointSize : 2*PointSize])
	CL, _ := curve.FromBytes(accBytes[2*PointSize : 3*PointSize])
	CR, _ := curve.FromBytes(accBytes[3*PointSize : 4*PointSize])
	PubKey, _ := curve.FromBytes(accBytes[4*PointSize : 5*PointSize])
	return &Account{
		Index:   index,
		AssetId: tokenId,
		Balance: &zecrey.ElGamalEnc{
			CL: CL,
			CR: CR,
		},
		PubKey: PubKey,
	}
}

func mockAccountHash(account *Account, h hash.Hash) []byte {
	h.Reset()
	res := SerializeAccount(account)
	h.Write(res[:])
	return h.Sum([]byte{})
}

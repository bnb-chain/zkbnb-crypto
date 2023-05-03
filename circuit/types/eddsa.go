/*
 * Copyright © 2022 ZkBNB Protocol
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

package types

import (
	"errors"

	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/signature/eddsa"
)

func VerifyEddsaSig(flag Variable, api API, hFunc MiMC, hashVal Variable, pk PublicKeyConstraints, sig eddsa.Signature) error {
	curve, err := twistededwards.NewEdCurve(api, tedwards.BN254)
	if err != nil {
		return err
	}
	err = verifySignature(flag, curve, sig, hashVal, pk, &hFunc)
	if err != nil {
		return err
	}
	return nil
}

func verifySignature(flag Variable, curve twistededwards.Curve, sig eddsa.Signature, msg frontend.Variable, pubKey PublicKeyConstraints, hash hash.Hash) error {

	// compute H(R, A, M)
	hash.Write(sig.R.X)
	hash.Write(sig.R.Y)
	hash.Write(pubKey.A.X)
	hash.Write(pubKey.A.Y)
	hash.Write(msg)
	hRAM := hash.Sum()

	base := twistededwards.Point{
		X: curve.Params().Base[0],
		Y: curve.Params().Base[1],
	}

	//[S]G-[H(R,A,M)]*A
	_A := curve.Neg(pubKey.A)
	Q := curve.DoubleBaseScalarMul(base, _A, sig.S, hRAM)
	Q.X = curve.API().Select(flag, Q.X, base.X)
	Q.Y = curve.API().Select(flag, Q.Y, base.Y)
	curve.AssertIsOnCurve(Q)

	//[S]G-[H(R,A,M)]*A-R
	Q = curve.Add(curve.Neg(Q), sig.R)

	// [cofactor]*(lhs-rhs)
	log := logger.Logger()
	if !curve.Params().Cofactor.IsUint64() {
		err := errors.New("invalid cofactor")
		log.Err(err).Str("cofactor", curve.Params().Cofactor.String()).Send()
		return err
	}
	cofactor := curve.Params().Cofactor.Uint64()
	switch cofactor {
	case 4:
		Q = curve.Double(curve.Double(Q))
	case 8:
		Q = curve.Double(curve.Double(curve.Double(Q)))
	default:
		log.Warn().Str("cofactor", curve.Params().Cofactor.String()).Msg("curve cofactor is not implemented")
	}

	Q.X = curve.API().Select(flag, Q.X, 0)
	Q.Y = curve.API().Select(flag, Q.Y, 1)

	curve.API().AssertIsEqual(Q.X, 0)
	curve.API().AssertIsEqual(Q.Y, 1)

	return nil
}

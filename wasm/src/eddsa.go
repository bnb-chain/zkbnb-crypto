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

package src

import (
	"bytes"
	"encoding/hex"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"syscall/js"

	curve "github.com/bnb-chain/zkbnb-crypto/ecc/ztwistededwards/tebn254"
)

func GetEddsaPublicKey() js.Func {
	helperFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) != 1 {
			return "invalid params"
		}
		// read seed
		seed := args[0].String()
		sk, err := curve.GenerateEddsaPrivateKey(seed)
		if err != nil {
			return err.Error()
		}
		var buf bytes.Buffer
		buf.Write(sk.PublicKey.A.X.Marshal())
		buf.Write(sk.PublicKey.A.Y.Marshal())
		return hex.EncodeToString(buf.Bytes())
	})
	return helperFunc
}

func GetEddsaCompressedPublicKey() js.Func {
	helperFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) != 1 {
			return "invalid params"
		}
		// read seed
		seed := args[0].String()
		sk, err := curve.GenerateEddsaPrivateKey(seed)
		if err != nil {
			return err.Error()
		}
		var buf bytes.Buffer
		buf.Write(sk.PublicKey.Bytes())
		return hex.EncodeToString(buf.Bytes())
	})
	return helperFunc
}

func GenerateEddsaKey() js.Func {
	helperFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) != 1 {
			return "invalid params"
		}
		// read seed
		seed := args[0].String()
		sk, err := curve.GenerateEddsaPrivateKey(seed)
		if err != nil {
			return err.Error()
		}
		return hex.EncodeToString(sk.Bytes())
	})
	return helperFunc
}

func EddsaSign() js.Func {
	helperFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) != 2 {
			return "invalid params"
		}
		// read seed
		seed := args[0].String()
		sk, err := curve.GenerateEddsaPrivateKey(seed)
		if err != nil {
			return err.Error()
		}
		msg := args[1].String()
		signature, err := sk.Sign(frBytes(msg)[:], mimc.NewMiMC())
		if err != nil {
			return err.Error()
		}
		return hex.EncodeToString(signature)
	})
	return helperFunc
}

func EddsaVerify() js.Func {
	helperFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) != 3 {
			return "invalid params"
		}
		// read seed
		pkStr := args[0].String()
		signatureStr := args[1].String()
		msgStr := args[2].String()
		pkBytes, err := hex.DecodeString(pkStr)
		if err != nil {
			return err.Error()
		}
		pk := eddsa.PublicKey{}
		size, err := pk.SetBytes(pkBytes)
		if err != nil {
			return err.Error()
		}
		if size != 32 {
			return "invalid public key"
		}
		signature, err := hex.DecodeString(signatureStr)
		if err != nil {
			return err.Error()
		}
		isValid, err := pk.Verify(signature, frBytes(msgStr)[:], mimc.NewMiMC())
		if err != nil {
			return err.Error()
		}
		return isValid
	})
	return helperFunc
}

func frBytes(msg string) []byte {
	var x fr.Element
	x.SetBytes([]byte(msg))
	b := x.Bytes()
	return b[:]
}

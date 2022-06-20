package zecrey_legend

import (
	"bytes"
	"encoding/hex"
	curve "github.com/zecrey-labs/zecrey-crypto/ecc/ztwistededwards/tebn254"
)

func GetEddsaPublicKey(seed string) (pk string) {
	sk, err := curve.GenerateEddsaPrivateKey(seed)
	if err != nil {
		return err.Error()
	}
	var buf bytes.Buffer
	buf.Write(sk.PublicKey.A.X.Marshal())
	buf.Write(sk.PublicKey.A.Y.Marshal())
	return hex.EncodeToString(buf.Bytes())
}

func GenerateEddsaKey(seed string) (skStr string) {
	sk, err := curve.GenerateEddsaPrivateKey(seed)
	if err != nil {
		return err.Error()
	}
	return hex.EncodeToString(sk.Bytes())
}

package zecrey_legend

import (
	"bytes"
	"encoding/hex"
	curve "github.com/zecrey-labs/zecrey-crypto/ecc/ztwistededwards/tebn254"
)

func GetEddsaPublicKey(seed string) (pk string, err error) {
	sk, err := curve.GenerateEddsaPrivateKey(seed)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	buf.Write(sk.PublicKey.A.X.Marshal())
	buf.Write(sk.PublicKey.A.Y.Marshal())
	return hex.EncodeToString(buf.Bytes()), nil
}

func GetEddsaCompressedPublicKey(seed string) (pk string, err error) {
	sk, err := curve.GenerateEddsaPrivateKey(seed)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sk.PublicKey.Bytes()), nil
}

func GenerateEddsaKey(seed string) (skStr string, err error) {
	sk, err := curve.GenerateEddsaPrivateKey(seed)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sk.Bytes()), nil
}

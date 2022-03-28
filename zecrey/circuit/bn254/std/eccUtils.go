package std

import "github.com/consensys/gnark/std/algebra/twistededwards"

type EccTool struct {
	api    API
	params twistededwards.Curve
	Base   Point
}

func NewEccTool(api API, params twistededwards.Curve) *EccTool {
	var base Point
	base.X = params.Params().Base[0]
	base.Y = params.Params().Base[1]
	return &EccTool{api: api, params: params, Base: base}
}

func (tool *EccTool) Neg(a Point) Point {
	var p Point
	p = tool.params.Neg(a)
	return p
}

func (tool *EccTool) ScalarBaseMul(b Variable) Point {
	var p Point
	p = tool.params.ScalarMul(tool.Base, b)
	return p
}

func (tool *EccTool) ScalarMul(a Point, b Variable) Point {
	var p Point
	p = tool.params.ScalarMul(a, b)
	return p
}

func (tool *EccTool) Add(a, b Point) Point {
	var p Point
	p = tool.params.Add(a, b)
	return p
}

func (tool *EccTool) ZeroPoint() Point {
	var p Point
	p.X = 0
	p.Y = 1
	return p
}

func (tool *EccTool) ZeroElgamalEnc() ElGamalEncConstraints {
	var enc ElGamalEncConstraints
	enc.CL = tool.ZeroPoint()
	enc.CR = tool.ZeroPoint()
	return enc
}

func (tool *EccTool) Double(a Point) Point {
	return tool.params.Double(a)
}

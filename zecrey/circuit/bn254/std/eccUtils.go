package std

import "github.com/consensys/gnark/std/algebra/twistededwards"

type EccTool struct {
	api    API
	params twistededwards.EdCurve
	Base   Point
}

func NewEccTool(api API, params twistededwards.EdCurve) *EccTool {
	var base Point
	base.X = params.Base.X
	base.Y = params.Base.Y
	return &EccTool{api: api, params: params, Base: base}
}

func (tool *EccTool) Neg(a Point) Point {
	var p Point
	p.Neg(tool.api, &a)
	return p
}

func (tool *EccTool) ScalarBaseMul(b Variable) Point {
	var p Point
	p.ScalarMul(tool.api, &tool.Base, b, tool.params)
	return p
}

func (tool *EccTool) ScalarMul(a Point, b Variable) Point {
	var p Point
	p.ScalarMul(tool.api, &a, b, tool.params)
	return p
}

func (tool *EccTool) Add(a, b Point) Point {
	var p Point
	p.Add(tool.api, &a, &b, tool.params)
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

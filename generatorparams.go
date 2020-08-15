package main

import "fmt"
import "math/big"

//import "crypto/rand"
import "encoding/hex"

import "github.com/clearmatics/bn256"
import "golang.org/x/crypto/sha3"

var FIELD_MODULUS, w = new(big.Int).SetString("30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47", 16)
var GROUP_MODULUS, w1 = new(big.Int).SetString("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001", 16)

// this file basically implements curve based items

type GeneratorParams struct {
	G    *bn256.G1
	H    *bn256.G1
	GSUM *bn256.G1

	Gs *GeneratorVector
	Hs *GeneratorVector
}

// the number if already reduced
func HashtoNumber(input []byte) *big.Int {

	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(input)

	hash := hasher.Sum(nil)
	return new(big.Int).SetBytes(hash[:])
}

// calculate hash and reduce it by curve's order
func reducedhash(input []byte) *big.Int {
	return new(big.Int).Mod(HashtoNumber(input), bn256.Order)
}

func makestring64(input string) string {
	for len(input) != 64 {
		input = "0" + input
	}
	return input
}

func hextobytes(input string) []byte {
	ibytes, err := hex.DecodeString(input)
	if err != nil {
		panic(err)
	}
	return ibytes
}

// this should be merged , simplified  just as simple as 25519
func HashToPoint(seed *big.Int) *bn256.G1 {
	seed_reduced := new(big.Int)
	seed_reduced.Mod(seed, FIELD_MODULUS)

	p_1_4 := new(big.Int).Add(FIELD_MODULUS, new(big.Int).SetInt64(1))
	p_1_4 = p_1_4.Div(p_1_4, new(big.Int).SetInt64(4))

	for {
		tmp := new(big.Int)
		y, y_squared, y_resquare := new(big.Int), new(big.Int), new(big.Int) // basically y_sqaured = seed ^3 + 3 mod group order
		tmp.Exp(seed_reduced, new(big.Int).SetInt64(3), FIELD_MODULUS)
		y_squared.Add(tmp, new(big.Int).SetInt64(3))
		y_squared.Mod(y_squared, FIELD_MODULUS)

		y = y.Exp(y_squared, p_1_4, FIELD_MODULUS)

		y_resquare = y_resquare.Exp(y, new(big.Int).SetInt64(2), FIELD_MODULUS)

		if y_resquare.Cmp(y_squared) == 0 { // seed becomes x and y iis usy
			xstring := seed_reduced.Text(16)
			ystring := y.Text(16)

			var point bn256.G1
			xbytes, err := hex.DecodeString(makestring64(xstring))
			if err != nil {
				panic(err)
			}
			ybytes, err := hex.DecodeString(makestring64(ystring))
			if err != nil {
				panic(err)
			}

			point.Unmarshal(append(xbytes, ybytes...))
			return &point

		}
		seed_reduced.Add(seed_reduced, new(big.Int).SetInt64(1))
		seed_reduced.Mod(seed_reduced, FIELD_MODULUS)
	}

	return nil
}

func NewGeneratorParams(count int) *GeneratorParams {
	GP := &GeneratorParams{}
	var zeroes [64]byte

	GP.G = HashToPoint(HashtoNumber([]byte(PROTOCOL_CONSTANT + "G"))) // this is same as mybase or vice-versa
	GP.H = HashToPoint(HashtoNumber([]byte(PROTOCOL_CONSTANT + "H")))

	var gs, hs []*bn256.G1

	GP.GSUM = new(bn256.G1)
	GP.GSUM.Unmarshal(zeroes[:])

	for i := 0; i < count; i++ {
		gs = append(gs, HashToPoint(HashtoNumber(append([]byte(PROTOCOL_CONSTANT+"G"), hextobytes(makestring64(fmt.Sprintf("%x", i)))...))))
		hs = append(hs, HashToPoint(HashtoNumber(append([]byte(PROTOCOL_CONSTANT+"H"), hextobytes(makestring64(fmt.Sprintf("%x", i)))...))))

		GP.GSUM = new(bn256.G1).Add(GP.GSUM, gs[i])
	}
	GP.Gs = NewGeneratorVector(gs)
	GP.Hs = NewGeneratorVector(hs)

	return GP
}

func NewGeneratorParams3(h *bn256.G1, gs, hs *GeneratorVector) *GeneratorParams {
	GP := &GeneratorParams{}

	GP.G = HashToPoint(HashtoNumber([]byte(PROTOCOL_CONSTANT + "G"))) // this is same as mybase or vice-versa
	GP.H = h
	GP.Gs = gs
	GP.Hs = hs
	return GP
}

func (gp *GeneratorParams) Commit(blind *big.Int, gexps, hexps *FieldVector) *bn256.G1 {
	result := new(bn256.G1).ScalarMult(gp.H, blind)
	for i := range gexps.vector {
		result = new(bn256.G1).Add(result, new(bn256.G1).ScalarMult(gp.Gs.vector[i], gexps.vector[i]))
	}
	if hexps != nil {
		for i := range hexps.vector {
			result = new(bn256.G1).Add(result, new(bn256.G1).ScalarMult(gp.Hs.vector[i], hexps.vector[i]))
		}
	}
	return result
}

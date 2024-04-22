package sm3

import (
	"encoding/binary"
	"math/bits"
)

const outlen = 32 //输出杂凑值的长度(单位:字节)

var IV = []uint32{0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e}                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 //寄存器V的初始值
var Tj = []uint32{0x79cc4519, 0xf3988a32, 0xe7311465, 0xce6228cb, 0x9cc45197, 0x3988a32f, 0x7311465e, 0xe6228cbc, 0xcc451979, 0x988a32f3, 0x311465e7, 0x6228cbce, 0xc451979c, 0x88a32f39, 0x11465e73, 0x228cbce6, 0x9d8a7a87, 0x3b14f50f, 0x7629ea1e, 0xec53d43c, 0xd8a7a879, 0xb14f50f3, 0x629ea1e7, 0xc53d43ce, 0x8a7a879d, 0x14f50f3b, 0x29ea1e76, 0x53d43cec, 0xa7a879d8, 0x4f50f3b1, 0x9ea1e762, 0x3d43cec5, 0x7a879d8a, 0xf50f3b14, 0xea1e7629, 0xd43cec53, 0xa879d8a7, 0x50f3b14f, 0xa1e7629e, 0x43cec53d, 0x879d8a7a, 0x0f3b14f5, 0x1e7629ea, 0x3cec53d4, 0x79d8a7a8, 0xf3b14f50, 0xe7629ea1, 0xcec53d43, 0x9d8a7a87, 0x3b14f50f, 0x7629ea1e, 0xec53d43c, 0xd8a7a879, 0xb14f50f3, 0x629ea1e7, 0xc53d43ce, 0x8a7a879d, 0x14f50f3b, 0x29ea1e76, 0x53d43cec, 0xa7a879d8, 0x4f50f3b1, 0x9ea1e762, 0x3d43cec5} //常量,用于压缩函数(预处理)

// SM3内部状态结构体
type Working_State struct {
	V            [8]uint32  //寄存器,存储中间结果与最终结果
	W            [68]uint32 //寄存器,用于消息扩展
	W_PTR        int        //指针，指向寄存器W中下一个空元素
	Buf          [4]byte    //缓冲区，暂存不满4字节的输入
	Buf_PTR      int        //指针，指向缓冲区Buf中下一个空元素
	Input_Length int        //已输入字节数
}

// 布尔函数FF0
func FF0(x uint32, y uint32, z uint32) uint32 {
	return x ^ y ^ z
}

// 布尔函数FF1
func FF1(x uint32, y uint32, z uint32) uint32 {
	return (x & y) | (x & z) | (y & z)
}

// 布尔函数GG0
func GG0(x uint32, y uint32, z uint32) uint32 {
	return x ^ y ^ z
}

// 布尔函数GG1
func GG1(x uint32, y uint32, z uint32) uint32 {
	return (x & y) | ((^x) & z)
}

// 置换函数P0
func P0(x uint32) uint32 {
	num1 := bits.RotateLeft32(x, 9)
	num2 := bits.RotateLeft32(x, 17)
	return x ^ num1 ^ num2
}

// 置换函数P1
func P1(x uint32) uint32 {
	num1 := bits.RotateLeft32(x, 15)
	num2 := bits.RotateLeft32(x, 23)
	return x ^ num1 ^ num2
}

// SM3内部状态初始化
func (working_state *Working_State) Init() {
	working_state.V[0] = IV[0]
	working_state.V[1] = IV[1]
	working_state.V[2] = IV[2]
	working_state.V[3] = IV[3]
	working_state.V[4] = IV[4]
	working_state.V[5] = IV[5]
	working_state.V[6] = IV[6]
	working_state.V[7] = IV[7]
	working_state.W_PTR = 0
	working_state.Buf_PTR = 0
	working_state.Input_Length = 0
	for i := 0; i < len(working_state.W); i++ {
		working_state.W[i] = 0
	}
	for i := 0; i < len(working_state.Buf); i++ {
		working_state.Buf[i] = 0
	}
}

// 从输入的指定位置开始向W写入4字节
func (working_state *Working_State) Write(input []byte, ptr int) {
	working_state.W[working_state.W_PTR] = binary.BigEndian.Uint32(input[ptr : ptr+4])
	working_state.W_PTR++
	if working_state.W_PTR > 15 {
		working_state.Hash()
	}
}

// 填充函数
func (working_state *Working_State) Fill(input []byte) {
	length := len(input)
	i := 0
	if working_state.Buf_PTR != 0 {
		for i < length {
			working_state.Buf[working_state.Buf_PTR] = input[i]
			working_state.Buf_PTR++
			i++
			if working_state.Buf_PTR == 4 {
				working_state.Write(working_state.Buf[:], 0)
				working_state.Buf_PTR = 0
				break
			}
		}
	}
	n := ((length - i) & ^3) + i
	for i < n {
		working_state.Write(input, i)
		i += 4
	}
	for i < length {
		working_state.Buf[working_state.Buf_PTR] = input[i]
		working_state.Buf_PTR++
		i++
	}
	working_state.Input_Length += length
}

// 尾部填充函数
func (working_state *Working_State) Tail() {
	length := working_state.Input_Length << 3
	working_state.Fill([]byte{128})
	for working_state.Buf_PTR != 0 {
		working_state.Fill([]byte{0})
	}
	if working_state.W_PTR > 14 {
		working_state.W[working_state.W_PTR] = 0
		working_state.W_PTR++
		working_state.Hash()
	}
	for working_state.W_PTR < 14 {
		working_state.W[working_state.W_PTR] = 0
		working_state.W_PTR++
	}
	working_state.W[working_state.W_PTR] = uint32(length >> 32)
	working_state.W_PTR++
	working_state.W[working_state.W_PTR] = uint32(length)
	working_state.W_PTR++
}

// 消息扩展与压缩函数
func (working_state *Working_State) Hash() {
	for j := 16; j < 68; j++ {
		W3 := working_state.W[j-3]
		num1 := bits.RotateLeft32(W3, 15)
		W13 := working_state.W[j-13]
		num2 := bits.RotateLeft32(W13, 7)
		working_state.W[j] = P1(working_state.W[j-16]^working_state.W[j-9]^num1) ^ num2 ^ working_state.W[j-6]
	}
	A := working_state.V[0]
	B := working_state.V[1]
	C := working_state.V[2]
	D := working_state.V[3]
	E := working_state.V[4]
	F := working_state.V[5]
	G := working_state.V[6]
	H := working_state.V[7]
	for j := 0; j < 16; j++ {
		A12 := bits.RotateLeft32(A, 12)
		SS1 := bits.RotateLeft32(A12+E+Tj[j], 7)
		SS2 := SS1 ^ A12
		Wj := working_state.W[j] ^ working_state.W[j+4]
		TT1 := FF0(A, B, C) + D + SS2 + Wj
		TT2 := GG0(E, F, G) + H + SS1 + working_state.W[j]
		D = C
		C = bits.RotateLeft32(B, 9)
		B = A
		A = TT1
		H = G
		G = bits.RotateLeft32(F, 19)
		F = E
		E = P0(TT2)
	}
	for j := 16; j < 64; j++ {
		A12 := bits.RotateLeft32(A, 12)
		SS1 := bits.RotateLeft32(A12+E+Tj[j], 7)
		SS2 := SS1 ^ A12
		Wj := working_state.W[j] ^ working_state.W[j+4]
		TT1 := FF1(A, B, C) + D + SS2 + Wj
		TT2 := GG1(E, F, G) + H + SS1 + working_state.W[j]
		D = C
		C = bits.RotateLeft32(B, 9)
		B = A
		A = TT1
		H = G
		G = bits.RotateLeft32(F, 19)
		F = E
		E = P0(TT2)
	}
	working_state.V[0] ^= A
	working_state.V[1] ^= B
	working_state.V[2] ^= C
	working_state.V[3] ^= D
	working_state.V[4] ^= E
	working_state.V[5] ^= F
	working_state.V[6] ^= G
	working_state.V[7] ^= H
	working_state.W_PTR = 0
}

// 输出函数
func SM3(input []byte) [outlen]byte {
	working_state := new(Working_State)
	working_state.Init()
	working_state.Fill(input)
	working_state.Tail()
	working_state.Hash()
	length := len(working_state.V)
	var output [outlen]byte
	for i := 0; i < length; i++ {
		binary.BigEndian.PutUint32(output[i*4:i*4+4], working_state.V[i])
	}
	return output
}

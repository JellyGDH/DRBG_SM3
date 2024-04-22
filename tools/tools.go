package tools

import (
	"encoding/binary"
	"fmt"
	"math/bits"
)

// 整形->字节切片
func Int2Bytes(num int, n int) []byte {
	bytes := make([]byte, n)
	switch n {
	case 1:
		bytes[0] = byte(num)
	case 2:
		binary.BigEndian.PutUint16(bytes[0:2], uint16(num))
	case 4:
		binary.BigEndian.PutUint32(bytes[0:4], uint32(num))
	case 8:
		binary.BigEndian.PutUint64(bytes[0:8], uint64(num))
	case 55:
		binary.BigEndian.PutUint64(bytes[0:55], uint64(num))
	default:
		fmt.Println("Int2Bytes error!")
	}
	return bytes
}

// 字节切片->比特串
func Bytes2Bits(bytes []byte) string {
	var bits string
	for _, byte := range bytes {
		bits += fmt.Sprintf("%08b", byte)
	}
	return bits
}

// 字节切片异或
func Bytes_XOR(a []byte, b []byte) []byte {
	temp := make([]byte, 4)
	for i := 0; i < 4; i++ {
		temp[i] = a[i] ^ b[i]
	}
	return temp
}

// 字节切片右移
func Bytes_ShiftRight(a []byte, n int) []byte {
	temp := make([]byte, 4)
	for i := 0; i < 4; i++ {
		temp[i] = a[i] >> n
	}
	return temp
}

// 常量Tj预处理
func Get_Tj() {
	var Tj [64]uint32
	fmt.Print("{")
	for j := 0; j < 16; j++ {
		Tj[j] = 0x79cc4519
		fmt.Printf("0x%08x,", bits.RotateLeft32(Tj[j], j))
	}
	for j := 16; j < 64; j++ {
		n := j % 32
		Tj[j] = 0x7a879d8a
		if j == 63 {
			fmt.Printf("0x%08x}\n", bits.RotateLeft32(Tj[j], n))
		} else {
			fmt.Printf("0x%08x,", bits.RotateLeft32(Tj[j], n))
		}
	}
}

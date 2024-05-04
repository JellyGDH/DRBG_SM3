package drbg

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"slices"
	"time"
	
	"github.com/jellygdh/drbg_sm3/pool"
	"github.com/jellygdh/drbg_sm3/sm3"
	"github.com/jellygdh/drbg_sm3/tools"

	"github.com/shirou/gopsutil/host"
)

const (
	outlen                     = 256         //输出随机比特序列的长度(单位:比特)
	seedlen                    = 440         //种子的比长度(单位:比特)
	reseed_interval_in_counter = 1024        //重播种计数器阈值
	reseed_interval_in_time    = 60          //重播种时间阈值(单位:秒)
	min_entropy_input_length   = 256         //最小的熵输入长度(单位:比特)
	max_entropy_input_length   = 34359738368 //最大的熵输入长度(单位:比特)
)

var min_entropy = 256               //最小熵(单位:比特)
var nonce_counter = 0               //计数器,用于nonce生成
var Mode = -1                       //当前工作模式
var entropy_pool pool.Working_State //熵池

// DRBG内部状态结构体
type Working_State struct {
	V                []byte //比特串,为随机数发生器的内部状态变量,在每次调用DRBG时更新值
	C                []byte //常量,为随机数发生器的内部状态变量,在初始化和重播种时更新值
	Reseed_Counter   int    //重播种计数器值
	Last_Reseed_Time int    //重播种时间值
}

// DRBG内部状态更新
func (working_state *Working_State) New_WorkingState(V []byte, C []byte, Reseed_Counter int, Last_Reseed_Time int) {
	working_state.V = V
	working_state.C = C
	working_state.Reseed_Counter = Reseed_Counter
	working_state.Last_Reseed_Time = Last_Reseed_Time
}

// 选择工作模式
func Select_Mode(n int) {
	switch n {
	case 0:
		Mode = 0
		entropy_pool = pool.Create_Working_State_Mode0()
	case 1:
		Mode = 1
		entropy_pool = pool.Create_Working_State_Mode1()
	case 2:
		Mode = 2
		entropy_pool = pool.Create_Working_State_Mode2()
	case 3:
		Mode = 3
		entropy_pool = pool.Create_Working_State_Mode3()
	default:
		fmt.Println("Select_Mode error!")
	}
}

// nonce生成
func Get_Nonce() []byte {
	boot_time, _ := host.BootTime()
	timestamp := time.Now().Nanosecond()
	bytes1 := tools.Int2Bytes(int(boot_time), 4)
	bytes2 := tools.Int2Bytes(timestamp, 4)
	bytes3 := tools.Int2Bytes(nonce_counter, 4)
	hexStr := "331051e42be3c2139b4077728785ff2553d1d7ffc7c98377875581837ee6a99501bd28a12c491ea656e5666286fdabc56bb05d811596e9667b165367c7d2e4c8"
	bytes4, _ := hex.DecodeString(hexStr)
	nonce_counter++
	return slices.Concat(bytes1, bytes2, bytes3, bytes4)
}

// SM3派生函数,对输入字符串进行杂凑运算,返回长度为number_of_bits_to_return的比特串
func SM3_df(input_string []byte, number_of_bits_to_return int) []byte {
	temp := make([]byte, 0)
	len := math.Ceil(float64(number_of_bits_to_return) / float64(outlen))
	counter := 0x01
	number_of_bits_to_return_bytes := tools.Int2Bytes(number_of_bits_to_return, 4)
	for i := 0; i < int(len); i++ {
		counter_bytes := tools.Int2Bytes(counter, 1)
		bytes := sm3.SM3(slices.Concat(counter_bytes, number_of_bits_to_return_bytes, input_string))
		temp = append(temp, slices.Concat(temp, bytes[:])...)
		counter++
	}
	return temp[0 : number_of_bits_to_return/8]
}

// 从熵源获取一串比特
func Get_Entropy(min_entropy int, min_entropy_input_length int, max_entropy_input_length int) (int, []byte) {
	if max_entropy_input_length < entropy_pool.Pool_Length || min_entropy_input_length > 512 {
		fmt.Println("Get_Entropy error!")
		return -2, entropy_pool.Pool_Content
	} else if min_entropy_input_length > entropy_pool.Pool_Length {
		return -1, entropy_pool.Pool_Content
	} else {
		return 0, entropy_pool.Pool_Content
	}
}

// 更新熵源
func Update_Entropy() {
	switch Mode {
	case 0:
		entropy_pool.Update_Mode0()
	case 1:
		entropy_pool.Update_Mode1()
	case 2:
		entropy_pool.Update_Mode2()
	case 3:
		entropy_pool.Update_Mode3()
	default:
		fmt.Println("Update_Entropy error!")
	}
}

// 初始化函数
func (working_state *Working_State) SM3_DRBG_Instantiate(personalization_string string) {
	if Test_KnownAnswer() == -1 {
		fmt.Println("已知答案测试未通过!")
	}
	personalization_string_bytes := []byte(personalization_string)
	nonce := Get_Nonce()
	min_entropy = min_entropy_input_length
	i, entropy_input := Get_Entropy(min_entropy, min_entropy_input_length, max_entropy_input_length)
	for i == -1 {
		i, entropy_input = Get_Entropy(min_entropy, min_entropy_input_length, max_entropy_input_length)
	}
	seed_material := slices.Concat(entropy_input, nonce, personalization_string_bytes)
	seed := SM3_df(seed_material, seedlen)
	num := 0x00
	V := seed
	C := SM3_df(slices.Concat(tools.Int2Bytes(num, 1), V), seedlen)
	reseed_counter := 1
	current_time_in_second := time.Now().Second()
	working_state.New_WorkingState(V, C, reseed_counter, current_time_in_second)

}

// 重播种函数
func (working_state *Working_State) SM3_DRBG_Reseed(entropy_input []byte, addition_input []byte) {
	num1 := 0x01
	num2 := 0x00
	seed_material := slices.Concat(tools.Int2Bytes(num1, 1), entropy_input, working_state.V, addition_input)
	seed := SM3_df(seed_material, seedlen)
	V := seed
	C := SM3_df(slices.Concat(tools.Int2Bytes(num2, 1), V), seedlen)
	reseed_counter := 1
	current_time_in_second := time.Now().Second()
	working_state.New_WorkingState(V, C, reseed_counter, current_time_in_second)

}

// 输出函数
func (working_state *Working_State) SM3_DRBG_Generate(requested_number_of_bits int, addition_input string) []byte {
	addition_input_bytes := []byte(addition_input)
	if working_state.Reseed_Counter > reseed_interval_in_counter || (time.Now().Second()-working_state.Last_Reseed_Time) > reseed_interval_in_time {
		_, input_entropy := Get_Entropy(min_entropy, min_entropy_input_length, max_entropy_input_length)
		working_state.SM3_DRBG_Reseed(input_entropy, addition_input_bytes)
	}
	if len(addition_input) != 0 {
		num1 := 0x02
		W := sm3.SM3(slices.Concat(tools.Int2Bytes(num1, 1), working_state.V, addition_input_bytes))
		V_num := (binary.BigEndian.Uint64(working_state.V) + binary.BigEndian.Uint64(W[:])) % uint64(math.Pow(2, float64(seedlen)))
		V := tools.Int2Bytes(int(V_num), seedlen/8)
		working_state.New_WorkingState(V, working_state.C, working_state.Reseed_Counter, working_state.Last_Reseed_Time)
	}
	temp := sm3.SM3(working_state.V)
	returned_bits := temp[0:int(requested_number_of_bits/8)]
	num2 := 0x03
	H := sm3.SM3(slices.Concat(tools.Int2Bytes(num2, 1), working_state.V))
	V_num := (binary.BigEndian.Uint64(working_state.V) + binary.BigEndian.Uint64(H[:]) + binary.BigEndian.Uint64(working_state.C) + uint64(working_state.Reseed_Counter)) % uint64(math.Pow(2, float64(seedlen)))
	V := tools.Int2Bytes(int(V_num), seedlen/8)
	reseed_counter := working_state.Reseed_Counter + 1
	working_state.New_WorkingState(V, working_state.C, reseed_counter, working_state.Last_Reseed_Time)
	return returned_bits
}

// 熵估计
func Estimate_Entropy(entropy []byte) float64 {
	N0 := 0
	N1 := 0
	N00 := 0
	N01 := 0
	N10 := 0
	N11 := 0
	var last rune = -1
	entropy_bits := tools.Bytes2Bits(entropy)
	for _, i := range entropy_bits {
		if i == '0' {
			N0++
			if last == '0' {
				N00++
			} else {
				N10++
			}
		} else {
			N1++
			if last == '0' {
				N01++
			} else {
				N11++
			}
		}
		last = i
	}
	P0 := float64(N0) / float64(len(entropy_bits))
	P1 := 1 - P0
	P00 := float64(N00) / float64(N00+N01)
	P01 := float64(N01) / float64(N00+N01)
	P10 := float64(N10) / float64(N10+N11)
	P11 := float64(N11) / float64(N10+N11)
	PMAX := max(P0*math.Pow(P00, 127), P0*math.Pow(P01, 64)*math.Pow(P10, 63), P0*P01*math.Pow(P11, 126), P1*P10*math.Pow(P00, 126), P1*math.Pow(P10, 64)*math.Pow(P01, 63), P1*math.Pow(P11, 127))
	min_entropy := min(-math.Log2(PMAX)/128, 1)
	return min_entropy
}

// 熵估计(时间戳信息)
func Estimate_Entropy_Timestamp() {
	temp := make([]byte, 0)
	for i := 0; i < 1000000/8/4; i++ {
		temp = append(temp, pool.Get_Timestamp()...)
	}
	entropy_timestamp := Estimate_Entropy(temp)
	fmt.Println(entropy_timestamp)
}

// 熵估计(CPU信息)
func Estimate_Entropy_CPU() {
	temp := make([]byte, 0)
	for i := 0; i < 1000000/8/12; i++ {
		temp = append(temp, pool.Get_CPU()...)
	}
	entropy_cpu := Estimate_Entropy(temp)
	fmt.Println(entropy_cpu)
}

// 熵估计(内存信息)
func Estimate_Entropy_Mem() {
	temp := make([]byte, 0)
	for i := 0; i < 1000000/8/8; i++ {
		temp = append(temp, pool.Get_Mem()...)
	}
	entropy_mem := Estimate_Entropy(temp)
	fmt.Println(entropy_mem)
}

// 熵估计(磁盘信息)
func Estimate_Entropy_Disk() {
	temp := make([]byte, 0)
	for i := 0; i < 1000000/8/16; i++ {
		temp = append(temp, pool.Get_Disk()...)
	}
	entropy_disk := Estimate_Entropy(temp)
	fmt.Println(entropy_disk)
}

// 熵估计(网络信息)
func Estimate_Entropy_Net() {
	temp := make([]byte, 0)
	for i := 0; i < 1000000/8/8; i++ {
		temp = append(temp, pool.Get_Net()...)
	}
	entropy_net := Estimate_Entropy(temp)
	fmt.Println(entropy_net)
}

// 熵估计(系统随机数)
func Estimate_Entropy_SystemRandom() {
	temp := make([]byte, 0)
	for i := 0; i < 1000000/8/4; i++ {
		temp = append(temp, pool.Get_SystemRandom()...)
	}
	entropy_system := Estimate_Entropy(temp)
	fmt.Println(entropy_system)
}

// 熵估计(硬件随机数)
func Estimate_Entropy_HardwareRandom() {
	temp := make([]byte, 0)
	for i := 0; i < 1000000/8/4; i++ {
		temp = append(temp, pool.Get_HardwareRandom()...)
	}
	entropy_hardware := Estimate_Entropy(temp)
	fmt.Println(entropy_hardware)
}

// 已知答案测试
func Test_KnownAnswer() int {
	nonce_str := "012345670123456700000001331051e42be3c2139b4077728785ff2553d1d7ffc7c98377875581837ee6a99501bd28a12c491ea656e5666286fdabc56bb05d811596e9667b165367c7d2e4c8"
	nonce, _ := hex.DecodeString(nonce_str)
	min_entropy = min_entropy_input_length
	entropy_input_str := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30313233343536"
	entropy_input, _ := hex.DecodeString(entropy_input_str)
	seed_material := slices.Concat(entropy_input, nonce)
	seed := SM3_df(seed_material, seedlen)
	num := 0x00
	V := seed
	C := SM3_df(slices.Concat(tools.Int2Bytes(num, 1), V), seedlen)
	reseed_counter := 1
	current_time_in_second := time.Now().Second()
	working_state := new(Working_State)
	working_state.New_WorkingState(V, C, reseed_counter, current_time_in_second)
	var addition_input string
	result := working_state.SM3_DRBG_Generate(256, addition_input)
	var target = []byte{16, 66, 177, 210, 178, 83, 14, 30, 188, 16, 55, 84, 16, 74, 152, 207, 105, 39, 18, 250, 237, 126, 181, 85, 188, 160, 67, 28, 22, 116, 104, 191}
	flag := false
	if len(result) == len(target) {
		flag = true
		for i := 0; i < len(result); i++ {
			if result[i] != target[i] {
				flag = false
				break
			}
		}
	}
	if flag {
		return 0
	} else {
		return -1
	}
}

// 输出随机数样本
func (working_state *Working_State) Get_Sample(addition_input string) {
	file, _ := os.Create("sample.bin")
	defer file.Close()
	for i := 0; i < 125000000/32+1; i++ {
		_, _ = file.Write(working_state.SM3_DRBG_Generate(256, addition_input))
	}
	_ = file.Sync()
}

// 初始化
func Init_DRBG_SM3(Mode int, personalization_string string) *Working_State {
	go Select_Mode(Mode)
	working_state := new(Working_State)
	working_state.SM3_DRBG_Instantiate(personalization_string)
	return working_state
}

// 输出
func Get_DRBG_SM3(working_state *Working_State, addition_input string) string {
	random_bytes := working_state.SM3_DRBG_Generate(256, addition_input)
	return tools.Bytes2Bits(random_bytes)
}

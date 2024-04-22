package pool

import (
	crypto_rand "crypto/rand"
	"fmt"
	math_rand "math/rand"
	"slices"
	"time"

	"github.com/jellygdh/drbg_sm3/tools"

	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/mem"
	"github.com/shirou/gopsutil/net"
)

const Pool_Capacity = 512 //熵池的最大容量(单位:字节)

var table = []uint32{0x0, 0x3b6e20c8, 0x76dc4190, 0x4db26158, 0xedb88320, 0xd6d6a3e8, 0x9b64c2b0, 0xa00ae278} //常量,用于熵池填充
var B = []int{0, 0, 0, 0, 0, 0, 0}                                                                            //变量,用于健康测试
var Last_Timestamp []byte                                                                                     //上一个熵源(时间戳信息),用于健康测试
var Last_CPU []byte                                                                                           //上一个熵源(CPU信息),用于健康测试
var Last_Mem []byte                                                                                           //上一个熵源(内存信息),用于健康测试
var Last_Disk []byte                                                                                          //上一个熵源(磁盘信息),用于健康测试
var Last_Net []byte                                                                                           //上一个熵源(网络信息),用于健康测试
var Last_SystemRandom []byte                                                                                  //上一个熵源(系统随机数),用于健康测试
var Last_HardwareRandom []byte                                                                                //上一个熵源(硬件随机数),用于健康测试

// 熵池内部状态结构体
type Working_State struct {
	Pool_Content []byte //熵池的当前内容
	Pool_Length  int    //熵池的当前容量(单位:字节)
}

// 熵源1:时间戳信息(4字节)
func Get_Timestamp() []byte {
	bytes := tools.Int2Bytes(int(time.Now().UnixNano()), 4)
	return bytes
}

// 熵源2:CPU信息(12字节)
func Get_CPU() []byte {
	info, _ := cpu.Times(false)
	bytes1 := tools.Int2Bytes(int(info[0].User*1000000), 4)
	bytes2 := tools.Int2Bytes(int(info[0].System*1000000), 4)
	bytes3 := tools.Int2Bytes(int(info[0].Idle*1000), 4)
	return slices.Concat(bytes1, bytes2, bytes3)
}

// 熵源3:内存信息(8字节)
func Get_Mem() []byte {
	info1, _ := mem.VirtualMemory()
	info2, _ := mem.SwapMemory()
	bytes1 := tools.Int2Bytes(int(info1.Used), 4)
	bytes2 := tools.Int2Bytes(int(info2.Used), 4)
	return slices.Concat(bytes1, bytes2)
}

// 熵源4:磁盘信息(16字节)
func Get_Disk() []byte {
	info, _ := disk.IOCounters()
	bytes1 := tools.Int2Bytes(int(info["C:"].ReadCount), 2)
	bytes2 := tools.Int2Bytes(int(info["C:"].WriteCount), 2)
	bytes3 := tools.Int2Bytes(int(info["C:"].ReadBytes), 4)
	bytes4 := tools.Int2Bytes(int(info["C:"].WriteBytes), 4)
	bytes5 := tools.Int2Bytes(int(info["C:"].ReadTime), 2)
	bytes6 := tools.Int2Bytes(int(info["C:"].WriteTime), 2)
	return slices.Concat(bytes1, bytes2, bytes3, bytes4, bytes5, bytes6)
}

// 熵源5:网络信息(8字节)
func Get_Net() []byte {
	info, _ := net.IOCounters(false)
	bytes1 := tools.Int2Bytes(int(info[0].BytesSent), 4)
	bytes2 := tools.Int2Bytes(int(info[0].BytesRecv), 4)
	return slices.Concat(bytes1, bytes2)
}

// 熵源6(可选):系统随机数(4字节)
func Get_SystemRandom() []byte {
	math_rand.New(math_rand.NewSource(time.Now().UnixNano()))
	bytes := tools.Int2Bytes(math_rand.Intn(0xffffffff), 4)
	return bytes
}

// 熵源7(可选):硬件随机数(4字节)
func Get_HardwareRandom() []byte {
	bytes := make([]byte, 4)
	_, err := crypto_rand.Read(bytes)
	if err != nil {
		fmt.Println("Get_HardwareRandom error!")
	}
	return bytes
}

// 总熵源(56字节)
func Get_EntropySource() []byte {
	bytes := slices.Concat(Get_Timestamp(), Get_CPU(), Get_Mem(), Get_Disk(), Get_Net(), Get_SystemRandom(), Get_HardwareRandom())
	return bytes
}

// 熵池初始化
func (working_state *Working_State) Init() {
	working_state.Pool_Content = make([]byte, Pool_Capacity)
	for i := 0; i < 512; i++ {
		working_state.Pool_Content[i] = 0
	}
	working_state.Pool_Length = 0
	fmt.Println("熵池初始化完毕...")
}

// 熵池填充
func (working_state *Working_State) Fill(entropy_source []byte) {
	temp := make([]byte, 4)
	for i := 0; i < 128; i++ {
		copy(temp, tools.Bytes_XOR(entropy_source, working_state.Pool_Content[i*4:i*4+4]))
		copy(temp, tools.Bytes_XOR(temp, working_state.Pool_Content[((i+1)%128)*4:((i+1)%128)*4+4]))
		copy(temp, tools.Bytes_XOR(temp, working_state.Pool_Content[((i+25)%128)*4:((i+25)%128)*4+4]))
		copy(temp, tools.Bytes_XOR(temp, working_state.Pool_Content[((i+51)%128)*4:((i+51)%128)*4+4]))
		copy(temp, tools.Bytes_XOR(temp, working_state.Pool_Content[((i+76)%128)*4:((i+76)%128)*4+4]))
		copy(temp, tools.Bytes_XOR(temp, working_state.Pool_Content[((i+103)%128)*4:((i+103)%128)*4+4]))
		bytes := tools.Int2Bytes(int(table[temp[3]&7]), 4)
		copy(temp, tools.Bytes_XOR(tools.Bytes_ShiftRight(temp, 3), bytes))
		for j := 0; j < 4; j++ {
			working_state.Pool_Content[i*4+j] = temp[j]
			if working_state.Pool_Length < Pool_Capacity {
				working_state.Pool_Length++
			}
		}
	}
}

// 熵池更新_模式0
func (working_state *Working_State) Update_Mode0() {
	entropy_source := Get_EntropySource()
	if Test_Continue(entropy_source) == -1 {
		fmt.Println("熵源连续健康测试未通过!")
	}
	for i := 0; i < 12; i++ {
		working_state.Fill(entropy_source[i*4 : i*4+4])
	}
	fmt.Println("熵池更新完毕...")
}

// 熵池更新_模式1
func (working_state *Working_State) Update_Mode1() {
	entropy_source := Get_EntropySource()
	if Test_Continue(entropy_source) == -1 {
		fmt.Println("熵源连续健康测试未通过!")
	}
	for i := 0; i < 13; i++ {
		working_state.Fill(entropy_source[i*4 : i*4+4])
	}
	fmt.Println("熵池更新完毕...")
}

// 熵池更新_模式2
func (working_state *Working_State) Update_Mode2() {
	entropy_source := Get_EntropySource()
	if Test_Continue(entropy_source) == -1 {
		fmt.Println("熵源连续健康测试未通过!")
	}
	for i := 0; i < 14; i++ {
		if i == 12 {
			continue
		}
		working_state.Fill(entropy_source[i*4 : i*4+4])
	}
	fmt.Println("熵池更新完毕...")
}

// 熵池更新_模式3
func (working_state *Working_State) Update_Mode3() {
	entropy_source := Get_EntropySource()
	if Test_Continue(entropy_source) == -1 {
		fmt.Println("熵源连续健康测试未通过!")
	}
	for i := 0; i < 14; i++ {
		working_state.Fill(entropy_source[i*4 : i*4+4])
	}
	fmt.Println("熵池更新完毕...")
}

// 熵池创建_模式0
func Create_Working_State_Mode0() Working_State {
	if Test_Start() == -1 {
		fmt.Println("熵源上电健康测试未通过!")
	}
	working_state := new(Working_State)
	working_state.Init()
	working_state.Update_Mode0()
	fmt.Println("熵池创建完毕...", "当前工作模式:0")
	return *working_state
}

// 熵池创建_模式1
func Create_Working_State_Mode1() Working_State {
	if Test_Start() == -1 {
		fmt.Println("熵源上电健康测试未通过!")
	}
	working_state := new(Working_State)
	working_state.Init()
	working_state.Update_Mode1()
	fmt.Println("熵池创建完毕...", "当前工作模式:1")
	return *working_state
}

// 熵池创建_模式2
func Create_Working_State_Mode2() Working_State {
	if Test_Start() == -1 {
		fmt.Println("熵源上电健康测试未通过!")
	}
	working_state := new(Working_State)
	working_state.Init()
	working_state.Update_Mode2()
	fmt.Println("熵池创建完毕...", "当前工作模式:2")
	return *working_state
}

// 熵池创建_模式3
func Create_Working_State_Mode3() Working_State {
	if Test_Start() == -1 {
		fmt.Println("熵源上电健康测试未通过!")
	}
	working_state := new(Working_State)
	working_state.Init()
	working_state.Update_Mode3()
	fmt.Println("熵池创建完毕...", "当前工作模式:3")
	return *working_state
}

// 健康测试
func Health_Test(entropy_source []byte, last []byte, n int) int {
	A := last
	B[n] = 1
	X := entropy_source
	flag := false
	if len(X) == len(A) {
		flag = true
		for i := 0; i < len(X); i++ {
			if X[i] != A[i] {
				flag = false
				break
			}
		}
	}
	if flag {
		B[n]++
		if B[n] > 10 {
			return -1
		}
	} else {
		B[n] = 1
	}
	return 0
}

// 上电健康测试函数
func Test_Start() int {
	for i := 0; i < 1024; i++ {
		temp := Get_Timestamp()
		if Health_Test(temp, Last_Timestamp, 0) == -1 {
			return -1
		}
		Last_Timestamp = temp
	}
	for i := 0; i < 1024; i++ {
		temp := Get_CPU()
		if Health_Test(temp, Last_CPU, 1) == -1 {
			return -1
		}
		Last_CPU = temp
	}
	for i := 0; i < 1024; i++ {
		temp := Get_Mem()
		if Health_Test(temp, Last_Mem, 2) == -1 {
			return -1
		}
		Last_Mem = temp
	}
	for i := 0; i < 1024; i++ {
		temp := Get_Disk()
		if Health_Test(temp, Last_Disk, 3) == -1 {
			return -1
		}
		Last_Disk = temp
	}
	for i := 0; i < 1024; i++ {
		temp := Get_Net()
		if Health_Test(temp, Last_Net, 4) == -1 {
			return -1
		}
		Last_Net = temp
	}
	for i := 0; i < 1024; i++ {
		temp := Get_SystemRandom()
		if Health_Test(temp, Last_SystemRandom, 5) == -1 {
			return -1
		}
		Last_SystemRandom = temp
	}
	for i := 0; i < 1024; i++ {
		temp := Get_HardwareRandom()
		if Health_Test(temp, Last_HardwareRandom, 6) == -1 {
			return -1
		}
		Last_HardwareRandom = temp
	}
	return 0
}

// 连续健康测试函数
func Test_Continue(entropy_source []byte) int {
	if Health_Test(entropy_source[0:4], Last_Timestamp, 0) == -1 {
		return -1
	}
	Last_Timestamp = entropy_source[0:4]
	if Health_Test(entropy_source[4:16], Last_CPU, 1) == -1 {
		return -1
	}
	Last_CPU = entropy_source[4:16]
	if Health_Test(entropy_source[16:24], Last_Mem, 2) == -1 {
		return -1
	}
	Last_Mem = entropy_source[16:24]
	if Health_Test(entropy_source[24:40], Last_Disk, 3) == -1 {
		return -1
	}
	Last_Disk = entropy_source[24:40]
	if Health_Test(entropy_source[40:48], Last_Net, 4) == -1 {
		return -1
	}
	Last_Net = entropy_source[40:48]
	if Health_Test(entropy_source[48:52], Last_Net, 5) == -1 {
		return -1
	}
	Last_SystemRandom = entropy_source[48:52]
	if Health_Test(entropy_source[52:56], Last_Net, 6) == -1 {
		return -1
	}
	Last_HardwareRandom = entropy_source[52:56]
	return 0
}

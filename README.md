## 这是一个探测WireGuard服务器存活状态的小工具

### 使用方法

1. 准备一个握手包（以01 00 00 00开头），将其内容填入代码中`packet`变量的定义内。
2. 生成要探测的服务器IP地址和端口号，写入到`ip.txt`中。
3. 编译和运行

```bash
go build -o main
# 每个地址发四个包，每个包的响应超时时间为400毫秒。选择没丢包的地址，按照延迟从低到高排序。
./main -c 4 -w 400 | grep 100% | sort -h -k 3
```

多运行几次效果更佳。

### 备注

#### 一些WARP入口IP和端口号，可据此生成要测试的地址

```
IPv4 Range: 162.159.193.0/24
IPv6 Range: 2606:4700:100::/48

2408, 500, 1701, 4500
```
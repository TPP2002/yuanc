# 澳洲出口节点与 Windows 一键客户端

客户自购小主机放在澳大利亚家庭宽带下当出口节点;Windows 客户端一键把全部流量经加密隧道从澳洲出口。节点程序(Linux,Python)负责幂等安装、自愈、自更新与账户管理;Windows 客户端(.NET 9 WPF,单文件 exe)负责登录、一键连接、断网保护与自动更新。

- 开工必读:`docs/开工须知.md`
- 技术方案:`docs/design/方案v2-中国客户端-澳洲出口.md`
- 客户交接文档:`docs/交接/`

目录规划:`node/`(节点程序与 pytest)、`winclient/`(Windows 客户端与 dotnet 测试)、`docs/`、`.github/workflows/`。

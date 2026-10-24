# 节点发布

脚本只需要 Python 标准库与现有 cryptography。Windows 开发机不执行 Linux 内核。

## Windows 客户端签名与托管

当前密钥登记：私钥为维护机仓库外 `C:/Users/Administrator/.secrets/yuanc-winclient-signing.pem`，公钥已内置于客户端。施工方不读取真实私钥；测试使用临时生成的密钥。

1. 按 `docs/winclient/打包与发布说明.md` 出包；本单不提高默认版本。
2. 执行 `python scripts/release/sign-winclient.py --exe build/release/YuanC-Client-<版本>.exe --key C:/Users/Administrator/.secrets/yuanc-winclient-signing.pem`。可指定 `--out`、`--version` 核对文件名及 `--min-service-version`（默认 0.1.0）。
3. 经管理通道把 exe、manifest.json、manifest.json.sig 三件复制到节点临时目录，执行 `exitnode winclient publish --exe <exe> --manifest <清单> --signature <签名>`，用 `exitnode winclient status` 核对。

清单使用排序键、UTF-8 紧凑 JSON；签名是对原始清单字节的 ECDSA P-256 / SHA-256 DER 签名。节点检查大小与哈希，客户端验签。发布后不要重新排版清单。生成新客户端密钥用 `gen-key.py --kind winclient --out <仓库外路径>`，输出的 SubjectPublicKeyInfo PEM 仅为公钥；换信任密钥需要独立安排可信过渡。

1. **生成密钥一次**：`python scripts/release/gen-key.py --out C:/secure/exitnode-signing.pem`。
   先创建仓库外的安全目录。私钥文件不得存在，脚本以 0600 创建；Windows 还应使用仅维护人员可访问的目录权限。
   把输出的公开 `PUBLIC_KEY` 常量填入 `node/exitnode/updater/trust.py`，然后安装初始可信节点。
   默认空公钥会拒绝升级。不要把私钥、私钥内容或含私钥的目录复制到仓库。
2. **打包签名**：`python scripts/release/build-node-package.py --version 0.2.0 --sing-box C:/release-input/sing-box --sing-box-version 1.13.21 --key C:/secure/exitnode-signing.pem --out C:/release-output`。
   二进制必须是目标节点架构的 Linux 版本。脚本不猜测内核版本；未传 `--sing-box-version` 时清单如实写 `unknown`。
   `--min-config-version` 默认 1，配置格式发生不兼容变化时显式指定最低要求。包内程序版本会更新为发布版本，工作区原文件不改。
   生成完整程序、模板、内核和逐文件哈希清单，以及对整个压缩包的独立签名。
3. **发布**：把同名的 `exitnode-<version>.tar.gz` 和 `.tar.gz.sig` 一起上传 GitHub Release，标签使用同一个版本号；或经管理隧道用 scp 将两文件复制到节点，再执行 `exitnode upgrade --file /维护目录/exitnode-<version>.tar.gz`。
   GitHub 私有仓令牌只放在节点 `secrets/github-token`，权限 0600，不放配置、URL 或发布说明。

发布前须复核信任公钥和包内实际程序版本。此脚本不上传、不部署、不创建定时更新任务。

## 当前密钥(2026-10-22)

首个签名密钥已生成:私钥在维护机 `C:/Users/Administrator/.secrets/yuanc-exitnode-signing.pem`(仓库外,0600),对应公钥已写入 `node/exitnode/updater/trust.py`。换密钥 = 重新生成 → 改 trust.py → 发一版由旧密钥签名的新程序(节点装上新公钥)→ 之后的包用新私钥签。

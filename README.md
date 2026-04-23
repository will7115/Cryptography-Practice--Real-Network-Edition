# 密码学实践 - 实网实战版

> Cryptography Practice - Real Network Edition

## 项目简介

本仓库是《密码学实践》书籍的配套代码库，核心思想是**从理论到战场**，强调实网实战的必要性。所有代码均可运行、攻击可复现、支持国密算法、全环境自动化部署。

## 特色

- **代码可跑**：每个章节的代码都经过测试验证
- **攻击可复现**：真实网络环境下的密码学攻击演示
- **国密原生支持**：完整支持 SM2/SM3/SM4 等国密算法
- **全环境自动化**：Docker 一键部署，环境配置零门槛

## 环境要求

- VMware Workstation 
- Ubuntu 22.04 LTS
- Docker & Docker Compose
- Python 3.9+
- OpenSSL / GmSSL
- Wireshark

## 快速开始

```bash
# 1. 克隆仓库
git clone https://github.com/your-username/cryptography-practice-real-network.git
cd cryptography-practice-real-network

# 2. 部署环境
docker-compose up -d


```

## 目录结构

```
cryptography-practice-real-network/
├── README.md               # 仓库总览、快速开始、环境要求
├── LICENSE                 # MIT 开源协议
├── docs/                   # 实验手册、攻击原理、工具指南
├── chapter01/              # 第一部分：实战环境构建
├── chapter02/              # 第二部分：流密码（RC4/LFSR/WEP攻击）
├── chapter03/              # 对称密码（AES/SM4/填充预言攻击）
├── chapter04/              # 哈希与MAC（SHA256/SM3/长度扩展攻击）
├── chapter05/              # 公钥密码（RSA/SM2/X.509证书）
├── chapter06/              # 密钥协商（DH/TLS1.3/降级攻击）
├── chapter07/              # 认证协议（TOTP/JWT攻击）
│   └── totp/               # TOTP 时间型一次性密码实现
├── chapter08/              # 零知识证明（zk-SNARKs演示）
├── chapter09/              # 综合实战：国密安全通信系统
│   └── secure_comm/        # 客户端+服务端安全通信
├── tools/                  # 核心工具链（OpenSSL/GmSSL/Wireshark脚本）
```

## 章节速查

| 章节                      | 主题         | 核心内容                          |
| ------------------------- | ------------ | --------------------------------- |
| [chapter01](./chapter01/) | 实战环境构建 | 虚拟化/Docker/云服务器配置        |
| [chapter02](./chapter02/) | 流密码       | RC4/LFSR/WEP攻击                  |
| [chapter03](./chapter03/) | 对称密码     | AES/SM4/填充预言攻击              |
| [chapter04](./chapter04/) | 哈希与MAC    | SHA256/SM3/长度扩展攻击           |
| [chapter05](./chapter05/) | 公钥密码     | RSA/SM2/X.509证书                 |
| [chapter06](./chapter06/) | 密钥协商     | DH/TLS1.3/降级攻击                |
| [chapter07](./chapter07/) | 认证协议     | TOTP/JWT攻击                      |
| [chapter08](./chapter08/) | 零知识证明   | zk-SNARKs演示                     |
| [chapter09](./chapter09/) | 综合实战     | 国密安全通信系统（客户端+服务端） |

## 开源协议

本项目采用 [MIT License](./LICENSE) 开源协议，允许商业/非商业使用，请保留版权声明。

## 问题反馈

如有问题或建议，请提交 [Issue](../../issues)。

---

**警告**：本仓库中的攻击演示代码仅供学习和授权测试使用，请勿用于非法用途。使用本代码造成的任何后果由使用者自行承担。

# TOTP-Based-Two-Factor-Authentication

> 基于时间的一次性密码（TOTP）双因素认证系统

## 1 实验目的

- 理解双因素认证（2FA）的核心原理与安全价值，掌握 TOTP 算法的工作流程与实现规范。
- 熟练搭建 Ubuntu 环境下的 C 语言开发环境，掌握 OpenSSL 库的安装与调用方法（重点使用 HMAC-SHA1 哈希功能）。
- 实现基于 TOTP 算法的双因素认证系统，完成**共享密钥生成、动态密码计算、密码验证**的全流程开发。
- 排查实验中的编译警告与运行问题，优化程序交互体验，验证系统功能的正确性与稳定性。

## 2 实验环境

- 运行环境：VMware 虚拟机 + Ubuntu 系统
- 编译工具：GCC 编译器、make 构建工具
- 依赖库：OpenSSL 开发库（提供 HMAC-SHA1、安全随机数）
- 编辑工具：nano 轻量文本编辑器

## 3 实验原理

### 3.1 双因素认证（2FA）

双因素认证是一种需要用户提供**两种不同类型认证因子**的安全验证方式，例如：

1. 账号密码（知识因子）
2. 动态口令、指纹、硬件令牌（ possession / 生物因子）

通过双重验证大幅提升账户安全性，有效防止密码泄露带来的风险。

### 3.2 TOTP 算法（Time-based One-time Password）

TOTP 是基于时间的一次性密码算法，广泛用于 Google 身份验证器、微软 Authenticator、各类网银/网盘二次验证。

**核心流程：**

1. **时间同步**：客户端与服务端时间保持一致
2. **时间窗口**：默认 30 秒一个时间片
3. **HMAC-SHA1 计算**：使用共享密钥 + 时间片生成动态密码
4. **动态密码**：输出 6 位数字一次性口令

遵循标准：**RFC 6238**

## 4 实验步骤

### 步骤 1：搭建实验环境

更新软件源并安装基础工具：

```bash
sudo apt update && sudo apt install -y gcc make
```

安装 OpenSSL 开发库：

```bash
sudo apt install -y libssl-dev
```

验证环境：

```bash
gcc --version
pkg-config --modversion openssl
```

### 步骤 2：创建并编写实验代码

进入实验目录：

```bash
cd ~/桌面
```

创建代码文件：

```bash
nano totp_2fa.c
```

粘贴以下完整代码：

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <math.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <arpa/inet.h>

/**************** TOTP核心配置（遵循RFC6238标准）*************/
#define TOTP_TIME_STEP 30    // 时间步长：30秒
#define TOTP_DIGITS 6        // 生成6位TOTP密码
#define TOTP_SECRET_LEN 16   // 共享密钥长度：16字节
#define TOTP_WINDOW 1        // 验证容错窗口：前后1个窗口
#define TOTP_MOD_VALUE 1000000 // 6位密码取模

/********************* 函数声明 ********************/
void generate_totp_secret(uint8_t secret[TOTP_SECRET_LEN]);
void secret_to_hex(const uint8_t secret[TOTP_SECRET_LEN], char hex_str[2*TOTP_SECRET_LEN+1]);
time_t get_current_timestamp();
int calculate_totp(const uint8_t secret[TOTP_SECRET_LEN], time_t timestamp, char totp[TOTP_DIGITS+1]);
int verify_totp(const uint8_t secret[TOTP_SECRET_LEN], const char input_totp[TOTP_DIGITS+1]);

/************************ 主函数 ************************/
int main() {
    uint8_t totp_secret[TOTP_SECRET_LEN];
    char secret_hex[2*TOTP_SECRET_LEN+1];
    char generated_totp[TOTP_DIGITS+1];
    char user_input[TOTP_DIGITS+1];
    time_t current_ts;

    // 生成共享密钥
    generate_totp_secret(totp_secret);
    secret_to_hex(totp_secret, secret_hex);

    printf("===== 双因素认证（TOTP）系统 =====\n");
    printf("【服务端】生成共享密钥（16字节，十六进制）：%s\n", secret_hex);
    printf("提示：该密钥已分发给客户端（如Google Authenticator），请妥善保管！\n\n");

    // 获取当前时间并计算TOTP
    current_ts = get_current_timestamp();
    calculate_totp(totp_secret, current_ts, generated_totp);

    printf("【当前时间】Unix时间戳：%ld | 剩余有效时间：%ld秒\n",
           current_ts, TOTP_TIME_STEP - (current_ts % TOTP_TIME_STEP));
    printf("【调试】当前正确的TOTP密码：%s\n", generated_totp);

    // 用户输入
    printf("请输入客户端生成的%d位TOTP动态密码：", TOTP_DIGITS);
    scanf("%s", user_input);
    getchar();

    // 验证
    if (verify_totp(totp_secret, user_input)) {
        printf("\n 验证成功！您已通过双因素认证，授予系统操作权限！\n");
    } else {
        printf("\n 验证失败！TOTP密码无效或已过期，请重新获取！\n");
    }

    return 0;
}

// 生成安全随机密钥
void generate_totp_secret(uint8_t secret[TOTP_SECRET_LEN]) {
    if (RAND_bytes(secret, TOTP_SECRET_LEN) != 1) {
        fprintf(stderr, "错误：生成随机密钥失败！\n");
        exit(EXIT_FAILURE);
    }
}

// 密钥转十六进制字符串
void secret_to_hex(const uint8_t secret[TOTP_SECRET_LEN], char hex_str[2*TOTP_SECRET_LEN+1]) {
    for (int i = 0; i < TOTP_SECRET_LEN; i++) {
        sprintf(hex_str + 2*i, "%02x", secret[i]);
    }
    hex_str[2*TOTP_SECRET_LEN] = '\0';
}

// 获取当前时间戳
time_t get_current_timestamp() {
    return time(NULL);
}

// TOTP核心计算
int calculate_totp(const uint8_t secret[TOTP_SECRET_LEN], time_t timestamp, char totp[TOTP_DIGITS+1]) {
    uint64_t T = (uint64_t)timestamp / TOTP_TIME_STEP;
    uint8_t T_bytes[8] = {0};
    T = htobe64(T);
    memcpy(T_bytes, &T, 8);

    uint8_t hmac_sha1[20] = {0};
    unsigned int hmac_len = 0;
    HMAC(EVP_sha1(), secret, TOTP_SECRET_LEN, T_bytes, 8, hmac_sha1, &hmac_len);

    int offset = hmac_sha1[19] & 0x0F;
    uint32_t code = (hmac_sha1[offset] & 0x7F) << 24 |
                    (hmac_sha1[offset+1] & 0xFF) << 16 |
                    (hmac_sha1[offset+2] & 0xFF) << 8 |
                    (hmac_sha1[offset+3] & 0xFF);

    int totp_num = code % TOTP_MOD_VALUE;
    sprintf(totp, "%06d", totp_num);
    return 0;
}

// TOTP验证（支持时间窗口容错）
int verify_totp(const uint8_t secret[TOTP_SECRET_LEN], const char input_totp[TOTP_DIGITS+1]) {
    time_t current_ts = get_current_timestamp();
    char calc_totp[TOTP_DIGITS+1];

    for (int i = -TOTP_WINDOW; i <= TOTP_WINDOW; i++) {
        time_t ts = current_ts + i * TOTP_TIME_STEP;
        if (calculate_totp(secret, ts, calc_totp) == 0) {
            if (strcmp(calc_totp, input_totp) == 0) {
                return 1;
            }
        }
    }
    return 0;
}
```

保存退出：
`Ctrl+O` → 回车 → `Ctrl+X`

### 步骤 3：编译代码

```bash
gcc totp_2fa.c -o totp_2fa -lssl -lcrypto -lm
```

### 步骤 4：运行与测试

```bash
./totp_2fa
```

**测试场景：**

- 有效时间内输入正确密码 → 验证成功
- 输入错误密码 → 验证失败
- 等待 30 秒过期后输入 → 验证失败

## 5 实验结果与总结

本次实验成功实现了**基于 TOTP 算法的双因素认证系统**，完整实现以下功能：

- 安全随机共享密钥生成
- 遵循 RFC6238 标准的 TOTP 6 位动态密码计算
- 基于 HMAC-SHA1 的哈希运算
- 带时间容错窗口的密码验证机制

通过实验，掌握了：

- 双因素认证（2FA）的安全原理与应用价值
- TOTP 算法的时间同步、时间片、哈希计算流程
- Ubuntu + C 语言 + OpenSSL 开发环境使用
- 密码学安全随机数、HMAC 函数的实际应用

TOTP 动态密码每 30 秒自动更新，结合唯一共享密钥，极大提升身份认证安全性，可有效抵御重放攻击、密码暴力破解等安全威胁。

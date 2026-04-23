#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <windows.h>
#include <wincrypt.h>
// 需确保OpenSSL头文件路径正确
#include <openssl/hmac.h>

// TOTP标准配置（RFC 6238）
#define TIME_STEP 30         // 时间步长（秒）
#define OTP_LENGTH 6         // OTP位数
#define SECRET_KEY_LENGTH 16 // 原始密钥字节长度（Base32编码后约26位）
#define TIME_WINDOW 1        // 时间窗口容错（±1个步长）

// Base32编码表（TOTP标准，仅大写字母+数字2-7）
static const char base32_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/**
 * Windows平台生成随机字节（替代/dev/urandom）
 * @param buffer 存储随机字节的缓冲区
 * @param length 要生成的字节长度
 * @return 成功返回0，失败返回-1
 */
int generate_random_bytes(uint8_t *buffer, size_t length)
{
    HCRYPTPROV hProv = 0;
    // 获取加密服务提供器
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
        printf("获取随机数生成器失败，错误码：%d\n", GetLastError());
        return -1;
    }
    // 生成真随机字节
    if (!CryptGenRandom(hProv, (DWORD)length, buffer))
    {
        printf("生成随机字节失败，错误码：%d\n", GetLastError());
        CryptReleaseContext(hProv, 0);
        return -1;
    }
    CryptReleaseContext(hProv, 0);
    return 0;
}

/**
 * 将二进制数据Base32编码（TOTP标准）
 * @param input 输入二进制数据
 * @param input_len 输入数据长度
 * @param output 输出Base32字符串缓冲区（需提前分配足够空间）
 * @return 输出字符串长度
 */
size_t base32_encode(const uint8_t *input, size_t input_len, char *output)
{
    size_t output_len = 0;
    uint32_t buffer = 0;
    int bits = 0;

    for (size_t i = 0; i < input_len; i++)
    {
        buffer = (buffer << 8) | input[i];
        bits += 8;
        while (bits >= 5)
        {
            bits -= 5;
            output[output_len++] = base32_table[(buffer >> bits) & 0x1F];
        }
    }

    // 处理剩余不足5位的部分
    if (bits > 0)
    {
        buffer <<= (5 - bits);
        output[output_len++] = base32_table[buffer & 0x1F];
    }

    // 去除填充符（兼容多数验证器）
    output[output_len] = '\0';
    return output_len;
}

/**
 * 生成TOTP共享密钥（Base32编码）
 * @param secret 存储Base32密钥的缓冲区（至少32字节）
 * @return 成功返回0，失败返回-1
 */
int generate_totp_secret(char *secret)
{
    uint8_t random_bytes[SECRET_KEY_LENGTH];
    if (generate_random_bytes(random_bytes, SECRET_KEY_LENGTH) != 0)
    {
        return -1;
    }
    base32_encode(random_bytes, SECRET_KEY_LENGTH, secret);
    return 0;
}

/**
 * Base32解码（用于将用户密钥转回二进制）
 * @param input Base32字符串
 * @param output 输出二进制缓冲区
 * @return 解码后的字节长度，失败返回-1
 */
int base32_decode(const char *input, uint8_t *output)
{
    int lookup[256] = {0};
    int i, bits = 0, buffer = 0, output_len = 0;

    // 构建Base32查找表
    for (i = 0; i < 32; i++)
    {
        lookup[(uint8_t)base32_table[i]] = i;
        if (i < 26)
        {
            lookup[(uint8_t)tolower(base32_table[i])] = i; // 兼容小写
        }
    }

    for (i = 0; input[i] != '\0'; i++)
    {
        if (lookup[(uint8_t)input[i]] == 0 && input[i] != base32_table[0])
        {
            continue; // 跳过无效字符
        }
        buffer = (buffer << 5) | lookup[(uint8_t)input[i]];
        bits += 5;
        if (bits >= 8)
        {
            bits -= 8;
            output[output_len++] = (buffer >> bits) & 0xFF;
        }
    }
    return output_len;
}

/**
 * 获取时间计数器（当前时间戳 / 30秒）
 * @return 时间计数器
 */
uint64_t get_time_counter()
{
    // Windows获取当前时间戳（秒）
    time_t current_time;
    time(&current_time);
    return (uint64_t)current_time / TIME_STEP;
}

/**
 * 生成6位TOTP一次性密码
 * @param secret Base32编码的共享密钥
 * @param counter 时间计数器（NULL则使用当前时间）
 * @return 6位OTP数字，失败返回-1
 */
int generate_totp(const char *secret, uint64_t *counter)
{
    uint8_t secret_bin[32] = {0};
    int secret_len = base32_decode(secret, secret_bin);
    if (secret_len <= 0)
    {
        printf("密钥解码失败\n");
        return -1;
    }

    // 使用当前时间计数器（如果未指定）
    uint64_t time_counter = counter ? *counter : get_time_counter();
    // 将计数器转换为8字节大端序（RFC 6238标准）
    uint8_t counter_bin[8] = {0};
    for (int i = 7; i >= 0; i--)
    {
        counter_bin[i] = time_counter & 0xFF;
        time_counter >>= 8;
    }

    // HMAC-SHA1计算
    uint8_t hmac_result[EVP_MAX_MD_SIZE] = {0};
    unsigned int hmac_len = 0;
    HMAC(EVP_sha1(), secret_bin, secret_len, counter_bin, 8, hmac_result, &hmac_len);

    // 动态截断：取最后4位作为偏移量
    int offset = hmac_result[hmac_len - 1] & 0x0F;
    // 提取4字节并转换为整数（去除最高位防止负数）
    uint32_t otp_int = (hmac_result[offset] & 0x7F) << 24 |
                       (hmac_result[offset + 1] & 0xFF) << 16 |
                       (hmac_result[offset + 2] & 0xFF) << 8 |
                       (hmac_result[offset + 3] & 0xFF);

    // 取后6位作为OTP
    return otp_int % 1000000;
}

/**
 * 验证TOTP一次性密码
 * @param secret Base32编码的共享密钥
 * @param user_otp 用户输入的6位OTP
 * @return 验证通过返回1，失败返回0
 */
int verify_totp(const char *secret, int user_otp)
{
    if (user_otp < 0 || user_otp > 999999)
    {
        return 0; // 无效的OTP格式
    }

    uint64_t current_counter = get_time_counter();
    // 检查当前±1个时间窗口（容错）
    for (int window = -TIME_WINDOW; window <= TIME_WINDOW; window++)
    {
        uint64_t counter = current_counter + window;
        int server_otp = generate_totp(secret, &counter);
        if (server_otp == user_otp)
        {
            return 1;
        }
    }
    return 0;
}

// 测试主函数
int main()
{
    // 1. 生成共享密钥
    char secret[32] = {0};
    if (generate_totp_secret(secret) != 0)
    {
        printf("Failed to generate secret key\n");
        system("pause");
        return 1;
    }
    printf("Generated Base32 secret key: %s\n", secret);

    // 2. 生成服务器端OTP
    int server_otp = generate_totp(secret, NULL);
    if (server_otp == -1)
    {
        printf("Failed to generate OTP\n");
        system("pause");
        return 1;
    }
    printf("Server generated 6-digit OTP: %06d\n", server_otp);

    // 3. 模拟用户输入并验证
    int user_otp;
    printf("Please enter the 6-digit verification code you received: ");
    if (scanf("%d", &user_otp) != 1)
    {
        printf("Invalid input format\n");
        system("pause");
        return 1;
    }

    if (verify_totp(secret, user_otp))
    {
        printf("Verification passed!\n");
    }
    else
    {
        printf("Verification failed! Please check the code or try again.\n");
    }

    system("pause");
    return 0;
}
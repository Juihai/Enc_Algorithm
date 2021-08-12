package com.shenruihai.symmetric;

import com.shenruihai.algorithm.symmetric.aes.AESUtils;
import org.junit.jupiter.api.Test;

public class AESTest {

    @Test
    public void aesTest() throws Exception {
        String input = "密码了不起!";
        String key = "1234567887654321";
        // 指定获取Cipher的算法,如果没有指定分组密码模式和填充模式,ECB/PKCS5Padding就是默认值
        // CBC模式,必须指定初始向量,初始向量中密钥的长度必须是16个字节
        // NoPadding模式,原文的长度必须是16个字节的整倍数
//        String transformation = "AES";

        // 指定获取密钥的算法
        System.out.println("加密前："+ input);
        String algorithm = "AES";
        String encryptAES = AESUtils.encrypt(input, key, algorithm);
        System.out.println("加密:" + encryptAES);
        String s = AESUtils.decrypt(encryptAES, key, algorithm);
        System.out.println("解密:" + s);

    }
}

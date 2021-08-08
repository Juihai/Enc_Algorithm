package com.shenruihai.encryption;

import com.shenruihai.encryption.aes.AESUtils;
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
        String transformation = "AES/CBC/PKCS5Padding";
        // 指定获取密钥的算法
        String algorithm = "AES";
        String encryptAES = AESUtils.encrypt(input, key, transformation, algorithm);
        System.out.println("加密:" + encryptAES);
        String s = AESUtils.decrypt(encryptAES, key, transformation, algorithm);
        System.out.println("解密:" + s);

    }
}

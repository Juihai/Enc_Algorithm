package com.shenruihai.symmetric;

import com.shenruihai.algorithm.symmetric.des.DESUtils;
import org.junit.jupiter.api.Test;

public class DESTest {

    @Test
    public void desTest() throws Exception {

        String message = "密码了不起!";
        String key = "12345678";
        // 指定获取Cipher的算法,如果没有指定分组密码模式和填充模式,ECB/PKCS5Padding就是默认值
        // CBC模式,必须指定初始向量,初始向量中密钥的长度必须是8个字节
        // NoPadding模式,原文的长度必须是8个字节的整倍数
//        String transformation = "DES";
        String transformation = "DES/CBC/PKCS5Padding";
        // 指定获取密钥的算法
        String algorithm = "DES";
        String messageEnc = DESUtils.encrypt(message, key, transformation, algorithm);
        System.out.println("加密:" + messageEnc);
        String messageDec = DESUtils.decrypt(messageEnc, key, transformation, algorithm);
        System.out.println("解密:" + messageDec);

    }

}

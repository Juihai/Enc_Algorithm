package com.shenruihai.asymmetric;

import com.shenruihai.algorithm.asymmetric.rsa.RSAUtils;
import org.junit.jupiter.api.Test;

import java.util.Map;

public class RSATset {

    @Test
    public void rsaTest() throws Exception {

        //生成公钥和私钥
        Map<Integer, String> keyMap = RSAUtils.genKeyPair();
        //原文
        String message = "密码了不起!";
        //密钥信息
        String publicKey = keyMap.get(0);
        String privateKey = keyMap.get(1);
        System.out.println("随机生成的公钥为:" + publicKey);
        System.out.println("随机生成的私钥为:" + privateKey);
        //对原文加密
        String messageEnc = RSAUtils.encrypt(message, publicKey);
        System.out.println(message + "\t加密后的字符串为:" + messageEnc);
        //对密文解密
        String messageDec = RSAUtils.decrypt(messageEnc, privateKey);
        System.out.println("还原后的字符串为:" + messageDec);

        // RSA签名
        String messageSign = RSAUtils.sign(message, privateKey);
        System.out.println("签名信息为:" + messageSign);
        // RSA验签
        boolean result = RSAUtils.verify(message, publicKey, messageSign);
        System.out.print("验签结果:" + result);

    }

}

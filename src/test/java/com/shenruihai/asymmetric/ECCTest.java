package com.shenruihai.asymmetric;

import com.shenruihai.algorithm.asymmetric.ecc.ECCUtils;
import org.junit.jupiter.api.Test;

import java.util.Map;

public class ECCTest {

    @Test
    public void eccTest() throws Exception {

        //生成公钥和私钥
        Map<Integer,String> map = ECCUtils.getGenerateKey();
        String publicKey = map.get(0);
        String privateKey = map.get(1);

        String message = "密码了不起!";

        System.out.println("随机生成的公钥为:" + publicKey);
        System.out.println("随机生成的私钥为:" + privateKey);
        String messageEnc = ECCUtils.encrypt(message, publicKey);
        System.out.println(message + "\t加密后的字符串为:" + messageEnc);

        String messageDec = ECCUtils.decrypt(messageEnc, privateKey);
        System.out.println("还原后的字符串为:" + messageDec);

        // RSA签名
        String messageSign = ECCUtils.sign(message, privateKey);
        System.out.println("签名信息为:" + messageSign);
        // RSA验签
        boolean result = ECCUtils.verify(message, publicKey, messageSign);
        System.out.print("验签结果:" + result);

    }
}

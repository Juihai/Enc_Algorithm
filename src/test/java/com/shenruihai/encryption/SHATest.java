package com.shenruihai.encryption;

import com.shenruihai.encryption.md.MDUtils;
import com.shenruihai.encryption.sha.SHAUtils;
import org.junit.jupiter.api.Test;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;

public class SHATest {

    @Test
    public void shaUtilTest() throws NoSuchAlgorithmException, UnsupportedEncodingException {
        String message = "密码了不起!";
        //用jdk实现:SHA1
        String msgJdkSha1 = SHAUtils.jdkSHA1(message);
        System.out.println("用jdkMD2 加密结果:" + msgJdkSha1);

        //用common codes实现实现:SHA1
        String msgCcSHA1 = SHAUtils.ccSHA1(message);
        System.out.println("用ccSHA1 加密结果:" + msgCcSHA1);

        //用common codes实现实现:SHA1
        String msgBcSHA1 = SHAUtils.bcSHA1(message);
        System.out.println("用bcSHA1 加密结果:" + msgBcSHA1);

        //用bouncy castle实现:SHA224
        String msgBcSHA224 = SHAUtils.bcSHA224(message);
        System.out.println("用bcSHA224 加密结果:" + msgBcSHA224);

        //用bouncy castle与jdk结合实现:SHA224
        String msgBcSHA224b = SHAUtils.bcSHA224b(message);
        System.out.println("用bcSHA224b 加密结果:" + msgBcSHA224b);

        //用jdk实现:SHA256
        String msgGenerateSha256 = SHAUtils.generateSha256(message);
        System.out.println("用generateSha256 加密结果:" + msgGenerateSha256);

    }
}

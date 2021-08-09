package com.shenruihai.digest;

import com.shenruihai.algorithm.digest.md.MDUtils;
import com.sun.xml.internal.org.jvnet.fastinfoset.EncodingAlgorithmException;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;

public class MDTest {

    @Test
    public void mdUtilTest() throws NoSuchAlgorithmException, EncodingAlgorithmException {
        String message = "密码了不起!";
        //用jdk实现:MD2
        String msgJdkMD2 = MDUtils.jdkMD2(message);
        System.out.println("用jdkMD2 加密结果:" + msgJdkMD2);

        //用common codes实现实现:MD2
        String msgCcMD2 = MDUtils.ccMD2(message);
        System.out.println("用ccMD2 加密结果:" + msgCcMD2);

        //用bouncy castle实现:MD4
        String msgBcMD4 = MDUtils.bcMD4(message);
        System.out.println("用bcMD4 加密结果:" + msgBcMD4);

        //用bouncy castle与jdk结合实现:MD4
        String msgBc2JdkMD4 = MDUtils.bc2jdkMD4(message);
        System.out.println("用bc2jdkMD4 加密结果:" + msgBc2JdkMD4);

        //用jdk实现:MD5
        String msgJdkMD5 = MDUtils.jdkMD5(message);
        System.out.println("用jdkMD5 加密结果:"+msgJdkMD5);
        System.out.println("用jdkMD5 加密结果16位:"+MDUtils.to16Byte(msgJdkMD5));

        //用bouncy castle实现:MD5
        String msgBcMD5 = MDUtils.bcMD5(message);
        System.out.println("用bcMD5 加密结果:"+msgBcMD5);
        System.out.println("用bcMD5 加密结果16位:"+MDUtils.to16Byte(msgBcMD5));

        //用common codes实现实现:MD5
        String msgCcMD5 = MDUtils.ccMD5(message);
        System.out.println("用ccMD5 加密结果:"+msgCcMD5);
        System.out.println("用ccMD5 加密结果16位:"+MDUtils.to16Byte(msgCcMD5));

    }
}

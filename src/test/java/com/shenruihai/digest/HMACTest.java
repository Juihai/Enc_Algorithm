package com.shenruihai.digest;

import com.shenruihai.algorithm.digest.hmac.HMACUtils;
import org.junit.jupiter.api.Test;

public class HMACTest {

    @Test
    public void HMACUtilTest() throws Exception {
        String message = "密码了不起!";
        //用jdk实现:
        String msgJdkHmacMD5 = HMACUtils.jdkHmacMD5(message);
        System.out.println("用jdkHmacMD5 加密结果:" + msgJdkHmacMD5);

        //用bouncy castle实现:
        String msgBcHmacMD5 = HMACUtils.bcHmacMD5(message);
        System.out.println("用bcHmacMD5 加密结果:" + msgBcHmacMD5);

    }
}

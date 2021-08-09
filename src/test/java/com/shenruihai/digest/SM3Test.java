package com.shenruihai.digest;

import com.shenruihai.algorithm.digest.sm3.SM3Digest;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

public class SM3Test {

    @Test
    public void testSM3()
    {
        byte[] md = new byte[32];
        byte[] message = "密码了不起!".getBytes();
        SM3Digest sm3 = new SM3Digest();
        sm3.update(message, 0, message.length);
        sm3.doFinal(md, 0);
        String s = new String(Hex.encode(md));
        System.out.println(s);
    }
}

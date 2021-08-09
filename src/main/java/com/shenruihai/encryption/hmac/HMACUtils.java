package com.shenruihai.encryption.hmac;

import java.math.BigInteger;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * MAC算法 (Message Authentication Codes消息认证码算法) 含有密钥的散列函数算法，
 * 兼容了MD和SHA算法的特性，并在此基础上加上了密钥。因此MAC算法也经常被称作HMAC算法。
 * 消息的散列值由只有通信双方知道的密钥来控制。此时Hash值称作MAC。
 *
 * 经过MAC算法得到的摘要值也可以使用十六进制编码表示，其摘要值得长度与实现算法的摘要
 * 值长度相同。例如 HmacSHA算法得到的摘要长度就是SHA1算法得到的摘要长度，都是160位
 * 二进制数，换算成十六进制的编码为40位。b
 *
 * @author juihai
 * @date 2021/5/27
 */
public class HMACUtils {

    // 用jdk实现:
    public static String jdkHmacMD5(String dataStr) throws Exception {
        // 初始化KeyGenerator
        KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacMD5");
        // 产生密钥
        SecretKey secretKey = keyGenerator.generateKey();
        // 获取密钥
        byte[] key = secretKey.getEncoded();
//        byte[] key = Hex.decodeHex(new char[]{'1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e'});
        // 还原密钥
        SecretKey restoreSecretKey = new SecretKeySpec(key, "HmacMD5");
        // 实例化MAC
        Mac mac = Mac.getInstance(restoreSecretKey.getAlgorithm());
        // 初始化MAC
        mac.init(restoreSecretKey);
        // 执行摘要
        byte[] hmacMD5Bytes = mac.doFinal(dataStr.getBytes());
        return Hex.encodeHexString(hmacMD5Bytes);
    }

    // 用bouncy castle实现:
    public static String bcHmacMD5(String dataStr) {
        HMac hmac = new HMac(new MD5Digest());
        // 必须是16进制的字符，长度必须是2的倍数
        hmac.init(new KeyParameter(org.bouncycastle.util.encoders.Hex.decode("123456789abcde")));
        hmac.update(dataStr.getBytes(), 0, dataStr.getBytes().length);
        // 执行摘要
        byte[] hmacMD5Bytes = new byte[hmac.getMacSize()];
        hmac.doFinal(hmacMD5Bytes, 0);
        BigInteger bigInteger = new BigInteger(1,hmacMD5Bytes);
        return bigInteger.toString(16);
    }

}

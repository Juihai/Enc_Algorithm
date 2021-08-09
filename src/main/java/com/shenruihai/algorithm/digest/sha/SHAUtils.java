package com.shenruihai.algorithm.digest.sha;

import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

/**
 * SHA（Secure Hash Algorithm）是由美国专门制定密码算法的标准机构——美国国家标准技术
 * 研究院（NIST）制定的，SHA系列算法的摘要长度分别为：SHA为20字节（160位）、SHA256为
 * 32字节（256位）、 SHA384为48字节（384位）、SHA512为64字节（512位），由于它产生的
 * 数据摘要的长度更长，因此更难以发生碰撞，因此也更为安全，它是未来数据摘要算法的发展方向。
 * 由于SHA系列算法的数据摘要长度较长，因此其运算速度与MD5相比，也相对较慢。
 *
 * 目前SHA1的应用较为广泛，主要应用于CA和数字证书中，另外在目前互联网中流行的BT软件中，
 * 也是使用SHA1来进行文件校验的。
 *
 * @author juihai
 * @date 2020/7/12
 */
public class SHAUtils {

    // 用jdk实现:SHA1
    public static String jdkSHA1(String dataStr) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA");
        md.update(dataStr.getBytes());
        byte[] bytes = md.digest();
        //byte[]转16进制
        BigInteger bigInt = new BigInteger(1, bytes);
        return bigInt.toString(16);
    }

    // 用common codes实现实现:SHA1
    public static String ccSHA1(String dataStr) {
        return DigestUtils.sha1Hex(dataStr.getBytes());
    }

    // 用bouncy castle实现:SHA1
    public static String bcSHA1(String dataStr) {
        Digest digest = new SHA1Digest();
        digest.update(dataStr.getBytes(), 0, dataStr.getBytes().length);
        byte[] sha1Bytes = new byte[digest.getDigestSize()];
        digest.doFinal(sha1Bytes, 0);
        BigInteger bigInt = new BigInteger(1, sha1Bytes);
        return bigInt.toString(16);
    }

    // 用bouncy castle实现:SHA224
    public static String bcSHA224(String dataStr) {
        Digest digest = new SHA224Digest();
        digest.update(dataStr.getBytes(), 0, dataStr.getBytes().length);
        byte[] sha224Bytes = new byte[digest.getDigestSize()];
        digest.doFinal(sha224Bytes, 0);
        BigInteger bigInt = new BigInteger(1, sha224Bytes);
        return bigInt.toString(16);
    }

    // 用bouncy castle与jdk结合实现:SHA224
    public static String bcSHA224b(String dataStr) throws NoSuchAlgorithmException {
        Security.addProvider(new BouncyCastleProvider());
        MessageDigest md = MessageDigest.getInstance("SHA224");
        md.update(dataStr.getBytes());
        BigInteger bigInt = new BigInteger(1, md.digest());
        return bigInt.toString(16);
    }

    // 用jdk实现:SHA256
    public static String generateSha256(String dataStr) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(dataStr.getBytes("UTF-8")); // Change this to "UTF-16" if needed
        byte[] digest = md.digest();
        BigInteger bigInt = new BigInteger(1, digest);
        return bigInt.toString(16);
    }

}

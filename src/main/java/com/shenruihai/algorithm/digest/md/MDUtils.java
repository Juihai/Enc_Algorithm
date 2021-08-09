package com.shenruihai.algorithm.digest.md;

import com.sun.xml.internal.org.jvnet.fastinfoset.EncodingAlgorithmException;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.crypto.digests.MD4Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

/**
 * 这是应用非常广泛的一个算法家族，尤其是 MD5（Message-Digest Algorithm 5，消息摘要算法版本5），
 * 它由MD2、MD3、MD4发展而来，由Ron Rivest（RSA公司）在1992年提出，目前被广泛应用于数据完整性校验、
 * 数据（消息）摘要、数据加密等。MD2、MD4、MD5 都产生16字节（128位）的校验值，一般用32位十六进制数
 * 表示。MD2的算法较慢但相对安全，MD4速度很快，但安全性下降，MD5比MD4更安全、速度更快。
 *
 * 目前在互联网上进行大文件传输时，都要得用MD5算法产生一个与文件匹配的、存储MD5值的文本文件（后缀名为 .md5
 * 或.md5sum），这样接收者在接收到文件后，就可以利用与 SFV 类似的方法来检查文件完整性，目前绝大多数大型
 * 软件公司或开源组织都是以这种方式来校验数据完整性，而且部分操作系统也使用此算法来对用户密码进行加密，
 * 另外，它也是目前计算机犯罪中数据取证的最常用算法。与MD5 相关的工具有很多，如 WinMD5等。
 *
 * @author juihai
 * @date 2021/5/27
 */
public class MDUtils {

    //摘要算法加盐
    private static final String slat = "mi@ma666!";

    // 用jdk实现:MD2
    public static String jdkMD2(String dataStr) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD2");
        byte[] md2Bytes = md.digest(dataStr.getBytes());
        return bytesToHexString(md2Bytes);
    }

    // 用common codes实现实现:MD2
    public static String ccMD2(String dataStr) {
        dataStr = dataStr + slat;
        return DigestUtils.md2Hex(dataStr.getBytes());
    }

    // 用bouncy castle实现:MD4
    public static String bcMD4(String dataStr) {
        MD4Digest digest = new MD4Digest();
        digest.update(dataStr.getBytes(), 0, dataStr.getBytes().length);
        byte[] md4Bytes = new byte[digest.getDigestSize()];
        digest.doFinal(md4Bytes, 0);
        return bytesToHexString(md4Bytes);
    }

    // 用bouncy castle与jdk结合实现:MD4
    public static String bc2jdkMD4(String dataStr) throws NoSuchAlgorithmException {
        Security.addProvider(new BouncyCastleProvider());
        MessageDigest md = MessageDigest.getInstance("MD4");
        byte[] md4Bytes = md.digest(dataStr.getBytes());
        return bytesToHexString(md4Bytes);
    }

    // 用jdk实现:MD5
    public static String jdkMD5(String dataStr) throws NoSuchAlgorithmException {

        dataStr = dataStr + slat;
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] md5Bytes = md.digest(dataStr.getBytes());
        return bytesToHexString(md5Bytes);
    }

    // 用bouncy castle实现:MD5
    public static String bcMD5(String dataStr) {
        MD5Digest digest = new MD5Digest();
        digest.update(dataStr.getBytes(), 0, dataStr.getBytes().length);
        byte[] md5Bytes = new byte[digest.getDigestSize()];
        digest.doFinal(md5Bytes, 0);
        return bytesToHexString(md5Bytes);

    }

    // 用common codes实现实现:MD5
    public static String ccMD5(String dataStr) {
        dataStr = dataStr + slat;
        return DigestUtils.md5Hex(dataStr.getBytes());
    }

    /**
     * MD5 16位截取32位中第9～25位
     * @param dataStr
     * @return
     * @throws EncodingAlgorithmException
     */
    public static String to16Byte(String dataStr) throws EncodingAlgorithmException {
        if(dataStr.length()!=32){
            throw new EncodingAlgorithmException("MD5加密计算错误.");
        }
        return dataStr.substring(8,24);
    }

    /**
     * byte[] 转 16进制
     */
    private static String bytesToHexString(byte[] src) {
        StringBuilder stringBuilder = new StringBuilder();
        if (src == null || src.length <= 0) {
            return null;
        }
        for (int i = 0; i < src.length; i++) {
            int v = src[i] & 0xFF;
            String hv = Integer.toHexString(v);
            if (hv.length() < 2) {
                stringBuilder.append(0);
            }
            stringBuilder.append(hv);
        }
        return stringBuilder.toString();
    }

}

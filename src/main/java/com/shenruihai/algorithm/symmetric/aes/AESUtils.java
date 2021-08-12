package com.shenruihai.algorithm.symmetric.aes;

import com.sun.org.apache.xml.internal.security.utils.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES加密,key的大小必须是16个字节
 * 如果没有指定分组密码模式和填充模式,ECB/PKCS5Padding就是默认值
 * 如果没有指定分组密码模式为CBC,必须指定初始向量,初始向量中密钥的长度必须是16个字节
 * NoPadding模式,原文的长度必须是16个字节的整倍数
 * @author juihai
 * @date 2021/4/13
 */
public class AESUtils {

    //获取Cipher对象的算法
    private static String transformation = "AES/CBC/PKCS5Padding";

    /**
     * 加密
     * @param input  明文
     * @param key   密钥(AES,密钥的长度必须是16个字节)
     * @param algorithm   获取密钥的算法
     * @return  返回密文
     * @throws Exception
     */
    public static String encrypt(String input, String key, String algorithm) throws Exception {
        // 1,获取Cipher对象
        Cipher cipher = Cipher.getInstance(transformation);
        // 指定密钥规则
        SecretKeySpec sks = new SecretKeySpec(key.getBytes(), algorithm);
        // 2.初始化向量的秘钥长度需要根据算法而定,des 8个字节长度  aes 16个字节长度
        //这里为了方便,统一使用传来的秘钥
        IvParameterSpec iv = new IvParameterSpec(key.getBytes());
        cipher.init(Cipher.ENCRYPT_MODE, sks, iv);
//        cipher.init(Cipher.ENCRYPT_MODE, sks);
        // 3. 加密
        byte[] bytes = cipher.doFinal(input.getBytes());
        // 对数据进行Base64编码
        String encode = Base64.encode(bytes);
        return encode;
    }

    /**
     * 解密
     * @param input  密文
     * @param key   密钥(AES,密钥的长度必须是16个字节)
     * @param algorithm   获取密钥的算法
     * @return 返回原文
     * @throws Exception
     */
    public static String decrypt(String input, String key, String algorithm) throws Exception {
        Cipher cipher = Cipher.getInstance(transformation);
        SecretKeySpec sks = new SecretKeySpec(key.getBytes(), algorithm);
        IvParameterSpec iv = new IvParameterSpec(key.getBytes());
        cipher.init(Cipher.DECRYPT_MODE, sks, iv);
//         cipher.init(Cipher.DECRYPT_MODE, sks);
        byte[] bytes = cipher.doFinal(Base64.decode(input));
        return new String(bytes);
    }

}

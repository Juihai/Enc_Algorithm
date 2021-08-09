package com.shenruihai.algorithm.asymmetric.rsa;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

/**
 * RSA
 * 非对称加密
 * 算法原理：根据数论，寻求两个大素数比较简单，而将它们的乘积进行因式分解却极其困难，因此可以将乘积公开作为加密密钥
 * @author juihai
 * @date 2021/4/13
 */
public class RSAUtils {

    public final static String ALGORITHM = "RSA";

    /**
     * 随机生成密钥对
     * @throws NoSuchAlgorithmException
     */
    public static Map<Integer, String> genKeyPair() throws NoSuchAlgorithmException {
        Map<Integer, String> keyMap = new HashMap<Integer, String>();  //用于封装随机产生的公钥与私钥
        // KeyPairGenerator类用于生成公钥和私钥对，基于RSA算法生成对象
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(ALGORITHM);
        // 初始化密钥对生成器，密钥大小为256-4096位
        keyPairGen.initialize(512, new SecureRandom());
        // 生成一个密钥对，保存在keyPair中
        KeyPair keyPair = keyPairGen.generateKeyPair();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();   // 得到私钥
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();  // 得到公钥
        // 将公钥和私钥保存到Map
        keyMap.put(0, new String(Base64.encodeBase64(publicKey.getEncoded())));  //0表示公钥
        keyMap.put(1, new String(Base64.encodeBase64((privateKey.getEncoded()))));  //1表示私钥

        return keyMap;
    }

    /**
     * RSA公钥加密
     * @param str 加密字符串
     * @param publicKey 公钥
     * @return 密文
     * @throws Exception  加密过程中的异常信息
     */
    public static String encrypt(String str, String publicKey) throws Exception{
        //base64编码的公钥
        byte[] keyBytes = Base64.decodeBase64(publicKey);
        RSAPublicKey pubKey = (RSAPublicKey) KeyFactory.getInstance(ALGORITHM).generatePublic(new X509EncodedKeySpec(keyBytes));
        //RSA加密
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        String outStr = Base64.encodeBase64String(cipher.doFinal(str.getBytes("UTF-8")));
        return outStr;
    }

    /**
     * RSA私钥解密
     * @param str 加密字符串
     * @param privateKey 私钥
     * @return 铭文
     * @throws Exception
     */
    public static String decrypt(String str, String privateKey) throws Exception{
        //64位解码加密后的字符串
        byte[] inputByte = Base64.decodeBase64(str.getBytes("UTF-8"));
        //base64编码的私钥
        byte[] keyBytes = Base64.decodeBase64(privateKey);
        RSAPrivateKey priKey = (RSAPrivateKey) KeyFactory.getInstance(ALGORITHM).generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
        //RSA解密
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, priKey);
        String outStr = new String(cipher.doFinal(inputByte));
        return outStr;
    }

    /**
     * 签名
     * @param str 待签名数据
     * @param privateKey 私钥
     * @return 签名
     */
    public static String sign(String str, String privateKey) throws Exception {
        //64位解码加密后的字符串
        byte[] inputByte = Base64.decodeBase64(str.getBytes("UTF-8"));
        //base64编码的私钥
        byte[] keyBytes = Base64.decodeBase64(privateKey);
        PrivateKey priKey = KeyFactory.getInstance(ALGORITHM).generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
        //RSA签名
        Signature signature = Signature.getInstance(RSASignatureEnum.MD5withRSA.toString());
        signature.initSign(priKey);
        signature.update(inputByte);
        return new String(Base64.encodeBase64(signature.sign()));
    }

    /**
     * 验签 TODO 该方法有问题，验签失败
     * @param src 原始字符串
     * @param publicKey 公钥
     * @param sign 签名
     * @return 是否验签通过
     */
    public static boolean verify(String src, String publicKey, String sign) throws Exception {
        //base64编码的公钥
        byte[] keyBytes = Base64.decodeBase64(publicKey);
        PublicKey pubKey =  KeyFactory.getInstance(ALGORITHM).generatePublic(new X509EncodedKeySpec(keyBytes));
        //RSA验签
        Signature signature = Signature.getInstance(RSASignatureEnum.MD5withRSA.toString());
        signature.initVerify(pubKey);
        signature.update(src.getBytes("UTF-8"));
        return signature.verify(Base64.decodeBase64(sign.getBytes("UTF-8")));
    }

}

package com.shenruihai.algorithm.asymmetric.ecc;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.NullCipher;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author juihai
 * @date 2021/4/13
 */
public class ECCUtils {

    /**
     * 192, 224, 239, 256, 384, 521
     * */
    private final static int KEY_SIZE = 256;//bit
    private final static String SIGNATURE = "SHA256withECDSA";

    public final static String ALGORITHM = "EC";
    public final static String PROVIDER = "BC";

    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    /**
     * 查看BouncyCastle库支持的算法
     * @param args
     */
    public static void main(String[] args) {
        Provider provider = new org.bouncycastle.jce.provider.BouncyCastleProvider();
        for (Provider.Service service : provider.getServices()) {
            System.out.println(service.getType() + ": "
                    + service.getAlgorithm());
        }

    }



    public static Map<Integer,String> getGenerateKey() throws Exception {
        //用于封装随机产生的公钥与私钥
        Map<Integer, String> keyMap = new HashMap();
        // KeyPairGenerator类用于生成公钥和私钥对，基于EC算法
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM, PROVIDER);
        keyPairGenerator.initialize(KEY_SIZE, new SecureRandom());
        // 生成一个密钥对，保存在keyPair中
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
        // 将公钥和私钥保存到Map
        keyMap.put(0, Base64.encodeBase64String(publicKey.getEncoded()));//0表示公钥
        keyMap.put(1, Base64.encodeBase64String(privateKey.getEncoded()));//1表示私钥
        return keyMap;
    }


    /**
     * 加密
     * @param str 原文
     * @param publicKey 公钥
     * @return
     * @throws Exception
     */
    public static String encrypt(String str,  String publicKey) throws Exception {
        //64位解码加密后的字符串
        byte[] inputByte = Base64.decodeBase64(str.getBytes("UTF-8"));
        //base64编码的公钥
        byte[] keyBytes = Base64.decodeBase64(publicKey);
        ECPublicKey pubKey = (ECPublicKey) KeyFactory.getInstance(ALGORITHM).generatePublic(new X509EncodedKeySpec(keyBytes));
        //加密
        // TODO Chipher不支持EC算法 未能实现
        Cipher cipher = new NullCipher();//Cipher.getInstance("ECIES", PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        String outStr = Base64.encodeBase64String(cipher.doFinal(inputByte));
        return outStr;
    }


    /**
     * 解密
     * @param str 密文
     * @param privateKey 私钥
     * @return
     * @throws Exception
     */
    public static String decrypt(String str, String privateKey) throws Exception {
        //64位解码加密后的字符串
        byte[] inputByte = Base64.decodeBase64(str.getBytes("UTF-8"));
        //base64编码的私钥
        byte[] keyBytes = Base64.decodeBase64(privateKey);
        ECPrivateKey priKey = (ECPrivateKey) KeyFactory.getInstance(ALGORITHM).generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
        //解密
        // TODO Chipher不支持EC算法 未能实现
        Cipher cipher = new NullCipher();//Cipher.getInstance("ECIES", PROVIDER);
        cipher.init(Cipher.DECRYPT_MODE, priKey);
        String outStr = Base64.encodeBase64String(cipher.doFinal(inputByte));
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
        ECPrivateKey priKey = (ECPrivateKey) KeyFactory.getInstance(ALGORITHM).generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
        //RSA签名
        Signature signature = Signature.getInstance(SIGNATURE);
        signature.initSign(priKey);
        signature.update(inputByte);
        return Base64.encodeBase64String(signature.sign());
    }

    /**
     * 验签
     *
     * @param src 原始字符串
     * @param publicKey 公钥
     * @param sign 签名
     * @return 是否验签通过
     */
    public static boolean verify(String src, String publicKey, String sign) throws Exception {
        //base64编码的公钥
        byte[] keyBytes = Base64.decodeBase64(publicKey);
        ECPublicKey pubKey = (ECPublicKey) KeyFactory.getInstance(ALGORITHM).generatePublic(new X509EncodedKeySpec(keyBytes));
        //RSA验签
        Signature signature = Signature.getInstance(SIGNATURE);
        signature.initVerify(pubKey);
        signature.update(src.getBytes("UTF-8"));
        return signature.verify(Base64.decodeBase64(sign.getBytes("UTF-8")));
    }

}

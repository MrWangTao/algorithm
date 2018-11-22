package com.xt.thx.algorithm.symmetric_encryption.aes;

import org.apache.commons.codec.binary.Hex;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author WangTao
 * Created at 18/11/21 下午6:39.
 */
public class XTAes {

    private static String HELLO_WORLD = "你好，世界";

    private static void jdkAES() throws Exception {
        KeyGenerator aes = KeyGenerator.getInstance("AES");
        aes.init(128);
        // 生成key
        SecretKey secretKey = aes.generateKey();
        byte[] keyBytes = secretKey.getEncoded();
        // 转换key
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
        // 加密
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        byte[] bytes = cipher.doFinal(HELLO_WORLD.getBytes());
        System.out.println("jdk aes encode:" + Hex.encodeHexString(bytes));
        // 解密
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        byte[] bytes1 = cipher.doFinal(bytes);
        System.out.println("jdk aes decode:" + new String(bytes1));
    }

    public static void main(String[] args) throws Exception {
        jdkAES();
    }

}

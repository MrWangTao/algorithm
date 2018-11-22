package com.xt.thx.algorithm.symmetric_encryption.pbe;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.security.SecureRandom;

/**
 * @author WangTao
 * Created at 18/11/22 上午10:22.
 */
public class XTPbe {

    private static String HELLO_WORLD = "你好，世界";

    // PBE特殊在口令化加盐
    private static void jdkPBE() throws Exception {
        // 初始化盐
        SecureRandom secureRandom = new SecureRandom();
        // 8为随机数
        byte[] salt = secureRandom.generateSeed(8);
        // 口令与密钥
        String password = "wang";
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
        SecretKey secretKey = factory.generateSecret(pbeKeySpec);
        // 加密, i 加密次数
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, 100);
        Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, pbeParameterSpec);
        byte[] bytes = cipher.doFinal(HELLO_WORLD.getBytes());
        System.out.println("jdk pbe encode hex:" + Hex.encodeHexString(bytes));
        System.out.println("jdk pbe encode base64:" + Base64.encodeBase64String(bytes));
        // 解密
        cipher.init(Cipher.DECRYPT_MODE, secretKey, pbeParameterSpec);
        byte[] result = cipher.doFinal(bytes);
        System.out.println("jdk pbe decode:" + new String(result));
    }

    public static void main(String[] args) throws Exception {
        jdkPBE();
    }

}

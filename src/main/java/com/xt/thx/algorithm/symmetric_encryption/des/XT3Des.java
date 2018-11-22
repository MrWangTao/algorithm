package com.xt.thx.algorithm.symmetric_encryption.des;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import java.security.SecureRandom;

/**
 * @author WangTao
 * Created at 18/11/21 下午6:04.
 */
public class XT3Des {

    private static String HELLO_WORLD = "你好，世界";

    private static void jdk3DES() throws Exception {
        // 生成key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede");
        // 生成key的时候需要指定keysize
//        keyGenerator.init(168);
        keyGenerator.init(new SecureRandom());
        // 根据generatorkey生成key
        SecretKey secretKey = keyGenerator.generateKey();
        System.out.println("key:" + secretKey);
        System.out.println("key:" + secretKey.getFormat());
        byte[] bytesKey = secretKey.getEncoded();
        System.out.println(bytesKey.length);
        // key 的转换
        DESedeKeySpec desKeySpec = new DESedeKeySpec(bytesKey);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("DESede");
        SecretKey convertSecretKey = factory.generateSecret(desKeySpec);

        // 加密  加密方式、工作模式、填充方式
        Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, convertSecretKey);
        byte[] bytes = cipher.doFinal(HELLO_WORLD.getBytes());
        System.out.println("jdk des encrypt:" + Hex.encodeHexString(bytes));

        // 解密
        cipher.init(Cipher.DECRYPT_MODE, convertSecretKey);
        byte[] bytes1 = cipher.doFinal(bytes);
        System.out.println("jdk des decode: " + new String(bytes1));
    }

    private static void bcSelf3DES() throws Exception {
        byte[] key = "1234567890123456".getBytes();
        byte[] bytes = HELLO_WORLD.getBytes();
        // BC原生Cipher
        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new DESedeEngine()));
        cipher.init(true, new KeyParameter(key));
        byte[] rv = new byte[cipher.getOutputSize(bytes.length)];
        int i = cipher.processBytes(bytes, 0, bytes.length, rv, 0);
        cipher.doFinal(rv, i);
        // 解密
        cipher.init(false, new KeyParameter(key));
        int i1 = cipher.processBytes(rv, 0, rv.length, rv, 0);
        cipher.doFinal(rv, i1);
        System.out.println(new String(rv));

    }

    public static void main(String[] args) throws Exception {
//        jdk3DES();
//        bcSelf3DES();
    }
}

package com.xt.thx.algorithm.symmetric_encryption.des;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

/**
 * @author WangTao
 * Created at 18/11/21 下午5:20.
 */
public class XTDes {

    private static String HELLO_WORLD = "你好，世界";

    private static void jdkDES() throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
        // 生成key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
        // 生成key的时候需要指定keysize
        keyGenerator.init(56);
        // 根据generatorkey生成key
        SecretKey secretKey = keyGenerator.generateKey();
        System.out.println("key:" + secretKey);
        System.out.println("key:" + secretKey.getFormat());
        byte[] bytesKey = secretKey.getEncoded();
        // key 的转换
        DESKeySpec desKeySpec = new DESKeySpec(bytesKey);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("DES");
        SecretKey convertSecretKey = factory.generateSecret(desKeySpec);

        // 加密  加密方式、工作模式、填充方式
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, convertSecretKey);
        byte[] bytes = cipher.doFinal(HELLO_WORLD.getBytes());
        System.out.println("jdk des encrypt:" + Hex.encodeHexString(bytes));

        // 解密
        cipher.init(Cipher.DECRYPT_MODE, convertSecretKey);
        byte[] bytes1 = cipher.doFinal(bytes);
        System.out.println("jdk des decode: " + new String(bytes1));

    }

    private static void bcDES() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        // 生成key s1如果不添加  那么依旧是SUN的provider
        KeyGenerator keyGenerator = KeyGenerator.getInstance("DES", "BC");
        // 生成key的时候需要指定keysize
        keyGenerator.init(56);
        System.out.println(keyGenerator.getProvider());
        // 根据generatorkey生成key
        SecretKey secretKey = keyGenerator.generateKey();
        System.out.println("key:" + secretKey);
        System.out.println("key:" + secretKey.getFormat());
        byte[] bytesKey = secretKey.getEncoded();
        // key 的转换
        DESKeySpec desKeySpec = new DESKeySpec(bytesKey);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("DES");
        SecretKey convertSecretKey = factory.generateSecret(desKeySpec);


        // 加密  加密方式、工作模式、填充方式
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, convertSecretKey);
        byte[] bytes = cipher.doFinal(HELLO_WORLD.getBytes());
        System.out.println("bc des encrypt:" + Hex.encodeHexString(bytes));

        // 解密
        cipher.init(Cipher.DECRYPT_MODE, convertSecretKey);
        byte[] bytes1 = cipher.doFinal(bytes);
        System.out.println("bc des decode: " + new String(bytes1));
    }

    private static void bcSelfDES() throws Exception {
        byte[] key = "12345678".getBytes();
        byte[] bytes = HELLO_WORLD.getBytes();
        // BC原生Cipher
        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new DESEngine()));
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
        jdkDES();
        bcDES();
        bcSelfDES();
    }

}

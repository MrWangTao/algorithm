package com.xt.thx.algorithm.digest;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.*;

/**
 * @author WangTao
 * Created at 18/11/21 上午11:48.
 */
public class JdkAlgorithm {

    private static final String HELLO_WORLD = "你好，世界";

    /**
     * jdkBase64
     * @throws IOException
     */
    private static void jdkBase64() throws IOException {
        BASE64Encoder encoder = new BASE64Encoder();
        String encode = encoder.encode(HELLO_WORLD.getBytes());
        System.out.println("encode:" + encode);
        BASE64Decoder decoder = new BASE64Decoder();
        byte[] bytes = decoder.decodeBuffer(encode);
        System.out.println("decode:" + new String(bytes));
    }

    /**
     * 消息摘要不可逆
     */
    private static void jdkMD5() throws NoSuchAlgorithmException {
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        byte[] digest = md5.digest(HELLO_WORLD.getBytes());
        // Hex在bc和cc中都有，我们通常使用apache cc
        // Hex 十六进制
        System.out.println("jdkMD5:" + Hex.encodeHexString(digest));
    }

    private static void jdkMD2() throws NoSuchAlgorithmException {
        MessageDigest md5 = MessageDigest.getInstance("MD2");
        byte[] digest = md5.digest(HELLO_WORLD.getBytes());
        // Hex在bc和cc中都有，我们通常使用apache cc
        // Hex 十六进制
        System.out.println("jdkMD2:" + Hex.encodeHexString(digest));
    }

    private static void jdkMD4() throws NoSuchAlgorithmException {
        // 如果我们要在jdk中使用MD5
        Security.addProvider(new BouncyCastleProvider()); // 动态配置，添加加密方式的一种实现方式
        MessageDigest md4 = MessageDigest.getInstance("md4");
        MessageDigest md5 = MessageDigest.getInstance("md5");
        Provider provider = md5.getProvider(); // sun
        System.out.println(provider.getName());
        byte[] digest = md4.digest(HELLO_WORLD.getBytes());
        System.out.println("jdk use bc md4: " + org.bouncycastle.util.encoders.Hex.toHexString(digest));
    }

    private static void jdkSHA1() throws NoSuchAlgorithmException {
        MessageDigest sha1 = MessageDigest.getInstance("sha");   // sha = sha-1
        byte[] digest = sha1.digest(HELLO_WORLD.getBytes());
        System.out.println("jdk sha1:" + Hex.encodeHexString(digest));
    }

    private static void jdkHmacMD5() throws NoSuchAlgorithmException, InvalidKeyException, DecoderException {
        // 初始化 KeyGenerator
        KeyGenerator hmacMD5 = KeyGenerator.getInstance("HmacMD5");
        // 产生密钥
        SecretKey secretKey = hmacMD5.generateKey();
        // 获取密钥
//        byte[] key = secretKey.getEncoded();
        byte[] key = Hex.decodeHex(new char[] {'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a'});
        // 还原密钥
        SecretKeySpec hmacMD51 = new SecretKeySpec(key, "HmacMD5");
        // 实例化mac
        Mac mac = Mac.getInstance(hmacMD51.getAlgorithm());
        // 初始化mac
        mac.init(hmacMD51);
        byte[] bytes = mac.doFinal(HELLO_WORLD.getBytes());
        System.out.println("HmacMd5: " + Hex.encodeHexString(bytes));

    }


    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeyException, DecoderException {
//        jdkBase64();
//        jdkMD5();
//        jdkMD4();
//        jdkMD2();
//        jdkSHA1();
        jdkHmacMD5();
    }

}

package com.xt.thx.algorithm.asymmetric_encryption.rsa;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * @author WangTao
 * Created at 18/11/22 下午2:08.
 */
public class XTRsa {

    private static String HELLO_WORLD = "你好，世界";

    private static void jdkRSA() throws Exception {
        // 1：初始化密钥
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(512);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey rsaPublicKey = keyPair.getPublic();
        PrivateKey rsaPrivateKey = keyPair.getPrivate();
        System.out.println("rasPublicKey: " + Base64.encodeBase64String(rsaPublicKey.getEncoded()));
        System.out.println("rasPrivateKey: " + Base64.encodeBase64String(rsaPrivateKey.getEncoded()));

        // 2：私钥加密、公钥解密 --- 加密
        // rsaPrivateKey.getEncoded() 返回的是 pcks8 私钥标准
        // Key编码规则 pcks8
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(rsaPrivateKey.getEncoded());
        KeyFactory rsaFactory = KeyFactory.getInstance("RSA");
        // 加密使用的key
        PrivateKey privateKey = rsaFactory.generatePrivate(pkcs8EncodedKeySpec);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] result = cipher.doFinal(HELLO_WORLD.getBytes());
        System.out.println("jdk rsa encode: " + Base64.encodeBase64String(result));

        // 3：私钥加密、公钥解密 --- 解密
        // x.509是密码学里公钥证书的标准格式
        // rsaPublicKey.getEncoded() 返回的是 x.509 公钥标准
        // Key编码规则x.509
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(rsaPublicKey.getEncoded());
        rsaFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = rsaFactory.generatePublic(x509EncodedKeySpec);
        cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] bytes = cipher.doFinal(result);
        System.out.println("jdk rsa decode : " + new String(bytes));

        // 4：公钥加密，私钥解密 --- 加密
        X509EncodedKeySpec x509EncodedKeySpec1 = new X509EncodedKeySpec(rsaPublicKey.getEncoded());
        rsaFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey1 = rsaFactory.generatePublic(x509EncodedKeySpec1);
        cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey1);
        byte[] bytes1 = cipher.doFinal(HELLO_WORLD.getBytes());
        System.out.println("jdk rsa encode : " + Base64.encodeBase64String(bytes1));

        // 5：公钥加密，私钥解密 --- 解密
        pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(rsaPrivateKey.getEncoded());
        rsaFactory = KeyFactory.getInstance("RSA");
        // 加密使用的key
        privateKey = rsaFactory.generatePrivate(pkcs8EncodedKeySpec);
        cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] result1 = cipher.doFinal(bytes1);
        System.out.println("jdk rsa decode: " + new String(result1));

    }

    public static void main(String[] args) throws Exception {
        jdkRSA();
    }

}

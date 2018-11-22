package com.xt.thx.algorithm.asymmetric_encryption.elgamal;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.DHParameterSpec;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * @author WangTao
 * Created at 18/11/22 下午2:35.
 */
public class XTEIgamal {

    private static String HELLO_WORLD = "你好，世界";

    private static void bcELGamal() throws Exception {
        // 需要动态添加provider
        Security.addProvider(new BouncyCastleProvider());
        // 初始化密钥
        AlgorithmParameterGenerator elGamal = AlgorithmParameterGenerator.getInstance("ElGamal");
        elGamal.init(256);
        AlgorithmParameters algorithmParameters = elGamal.generateParameters();
        DHParameterSpec parameterSpec = algorithmParameters.getParameterSpec(DHParameterSpec.class);
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ElGamal");
        keyPairGenerator.initialize(parameterSpec, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey aPublic = keyPair.getPublic();
        PrivateKey aPrivate = keyPair.getPrivate();
        System.out.println("elGamalPublicKey: " + Base64.encodeBase64String(aPublic.getEncoded()));
        System.out.println("elGamalPrivateKey: " + Base64.encodeBase64String(aPrivate.getEncoded()));

        // 4：公钥加密，私钥解密 --- 加密
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(aPublic.getEncoded());
        KeyFactory keyFactory = KeyFactory.getInstance("ElGamal");
        PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
        Cipher cipher = Cipher.getInstance("ElGamal");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        // java.security.InvalidKeyException: Illegal key size or default parameters
        // 错误原因：指密钥长度是受限制的，java运行时环境读到的是受限的policy文件。文件位于${java_home}/jre/lib/security
        /*
        * 去掉这种限制需要下载Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files.网址如下。
            下载包的readme.txt 有安装说明。就是替换${java_home}/jre/lib/security/ 下面的local_policy.jar和US_export_policy.jar
            jdk 5: http://www.oracle.com/technetwork/java/javasebusiness/downloads/java-archive-downloads-java-plat-419418.html#jce_policy-1.5.0-oth-JPR
            jdk6: http://www.oracle.com/technetwork/java/javase/downloads/jce-6-download-429243.html
            jdk7下载地址： http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html
            AES加密参考：http://blog.csdn.net/hbcui1984/article/details/5201247
        * */
        byte[] bytes1 = cipher.doFinal(HELLO_WORLD.getBytes());
        System.out.println("bc elGamal encode : " + Base64.encodeBase64String(bytes1));

        // 5：公钥加密，私钥解密 --- 解密
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(aPrivate.getEncoded());
        keyFactory = KeyFactory.getInstance("ElGamal");
        // 加密使用的key
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        cipher = Cipher.getInstance("ElGamal");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] result1 = cipher.doFinal(bytes1);
        System.out.println("bc elGamal decode: " + new String(result1));
    }

    public static void main(String[] args) throws Exception {
        bcELGamal();
    }
}

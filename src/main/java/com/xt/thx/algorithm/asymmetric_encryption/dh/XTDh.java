package com.xt.thx.algorithm.asymmetric_encryption.dh;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

/**
 * @author WangTao
 * Created at 18/11/22 上午11:08.
 */
public class XTDh {

    private static String HELLO_WORLD = "你好，世界";

    /*private static KeyPair senderKeyPair(){

    }*/

    private static void jdkDH() throws Exception {
        // 初始化发送方密钥
        KeyPairGenerator senderKeyPairGenerator = KeyPairGenerator.getInstance("DH");
        // 生成keyPair
        KeyPair senderKeyPair = senderKeyPairGenerator.generateKeyPair();
        // 发送方公钥，需要发送给接收方
        byte[] senderPublicKeyEnc = senderKeyPair.getPublic().getEncoded();

        // 初始化接收方的密钥
        KeyFactory receiveKeyFactory = KeyFactory.getInstance("DH");
        // 公钥是使用在这个地方的
        // 从发送方的密钥中获取参数，获取私钥
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(senderPublicKeyEnc);
        PublicKey receivePublicKey = receiveKeyFactory.generatePublic(x509EncodedKeySpec);
        DHParameterSpec params = ((DHPublicKey) receivePublicKey).getParams();
        KeyPairGenerator receiveKeyPairGenerator = KeyPairGenerator.getInstance("DH");
        receiveKeyPairGenerator.initialize(params);
        KeyPair receiveKeyPair = receiveKeyPairGenerator.generateKeyPair();
        PrivateKey receivePrivateKey = receiveKeyPair.getPrivate();
        byte[] receivePublicKeyEnc = receiveKeyPair.getPublic().getEncoded();
        // 密钥构建
        KeyAgreement receiveKeyAgreement = KeyAgreement.getInstance("DH");
        receiveKeyAgreement.init(receivePrivateKey);
        receiveKeyAgreement.doPhase(receivePublicKey, true);
        // 使用发送的公钥生成本地密钥
        SecretKey des = receiveKeyAgreement.generateSecret("DES");

        //
        KeyFactory dh = KeyFactory.getInstance("DH");
        x509EncodedKeySpec = new X509EncodedKeySpec(receivePublicKeyEnc);
        PublicKey publicKey = dh.generatePublic(x509EncodedKeySpec);
        KeyAgreement senderKeyAgreement = KeyAgreement.getInstance("DH");
        senderKeyAgreement.init(senderKeyPair.getPrivate());
        senderKeyAgreement.doPhase(publicKey, true);

        SecretKey senderDesKey = senderKeyAgreement.generateSecret("DES");
        if (Objects.equals(des, senderDesKey)) {
            System.out.println("双方密钥相同");
        }

        // 加密
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.ENCRYPT_MODE, senderDesKey);
        byte[] bytes = cipher.doFinal(HELLO_WORLD.getBytes());
        System.out.println("jdk dh encode: " + Base64.encodeBase64String(bytes));

        // 解密
        cipher.init(Cipher.DECRYPT_MODE, des);
        byte[] res = cipher.doFinal(bytes);
        System.out.println("jdk dh decode: " + new String(res));

    }

    public static void main(String[] args) throws Exception {
        jdkDH();
    }

}

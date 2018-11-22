package com.xt.thx.algorithm.digest;

import com.sun.crypto.provider.HmacMD5;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD4Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

/**
 * BC中不需要new，实例化， 静态方法
 *
 * @author WangTao
 * Created at 18/11/21 下午1:57.
 */
public class BouncyCastle {

    private static final String HELLO_WORLD = "你好，世界";

    private static void bcBase64() {
        byte[] encode = Base64.encode(HELLO_WORLD.getBytes());
        System.out.println("encode:" + new String(encode));
        byte[] decode = Base64.decode(encode);
        System.out.println("decode：" + new String(decode));
    }

    private static void bcMd4() {
        // bc本身
        MD4Digest md4Digest = new MD4Digest();
        md4Digest.update(HELLO_WORLD.getBytes(), 0, HELLO_WORLD.getBytes().length);
        byte[] md4Bytes = new byte[md4Digest.getDigestSize()];
        md4Digest.doFinal(md4Bytes, 0);
        System.out.println("bcMD4:" + org.bouncycastle.util.encoders.Hex.toHexString(md4Bytes));
    }

    private static void bcMD5() {
        MD5Digest md5Digest = new MD5Digest();
        md5Digest.update(HELLO_WORLD.getBytes(), 0, HELLO_WORLD.getBytes().length);
        byte[] md5Bytes = new byte[md5Digest.getDigestSize()];
        md5Digest.doFinal(md5Bytes, 0);
        System.out.println("bcMD5:" + org.bouncycastle.util.encoders.Hex.toHexString(md5Bytes));
    }

    private static void bcSHA1() {
        SHA1Digest sha1Digest = new SHA1Digest();
        sha1Digest.update(HELLO_WORLD.getBytes(), 0, HELLO_WORLD.getBytes().length);
        byte[] sha1Bytes = new byte[sha1Digest.getDigestSize()];
        sha1Digest.doFinal(sha1Bytes, 0);
        System.out.println("bc sha-1:" + org.bouncycastle.util.encoders.Hex.toHexString(sha1Bytes));

    }

    private static void bcHmacMD5() {
        HMac hMac = new HMac(new MD5Digest());
        hMac.init(new KeyParameter(org.bouncycastle.util.encoders.Hex.decode("aaaaaaaaaa")));
        hMac.update(HELLO_WORLD.getBytes(), 0, HELLO_WORLD.getBytes().length);
        byte[] bytes = new byte[hMac.getMacSize()];
        hMac.doFinal(bytes, 0);
        System.out.println("bc hmacMD5: " + org.bouncycastle.util.encoders.Hex.toHexString(bytes));
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
//        bcBase64();
//        bcMd4();
//        bcMD5();
//        bcSHA1();
        bcHmacMD5();
    }

}

package com.xt.thx.algorithm.digest;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.EncoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;

/**
 * @author WangTao
 * Created at 18/11/21 上午11:35.
 */
public class CommonsCodec {

    private static void base64(String str) throws EncoderException, DecoderException {
        Base64 base64 = new Base64();
        System.out.println("origin:" + str);
        byte[] encode = base64.encode(str.getBytes());
        System.out.println("encode:" + new String(encode));
        byte[] decode = base64.decode(encode);
        System.out.println("decode:" + new String(decode));
    }

    private static void ccMD5(String str){
        String s = DigestUtils.md5Hex(str.getBytes());
        System.out.println("cc MD5:" + s);
    }

    private static void ccSHA1() {
        System.out.println("cc SHA1 - 1 :" + DigestUtils.sha1Hex("你好，世界"));
        System.out.println("cc SHA1 - 2 :" + DigestUtils.sha1Hex("你好，世界".getBytes()));
    }

    public static void main(String[] args) throws Exception {
//        base64("你好，世界");
//        ccMD5("你好，世界");
        ccSHA1();
    }

}

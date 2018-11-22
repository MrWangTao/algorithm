## 加密算法

### Base64
@see https://www.cnblogs.com/tingzi/archive/2012/08/17/2643742.html
+ Commons项目中用来处理常用的编码方法的工具类包，例如DES、SHA1、MD5、Base64, 及 hex, metaphone, soundex 等编码演算。
+ 官网下载地址：http://commons.apache.org/codec/

+ Base64常用方式
    - jdk
    - cc：Apache Commons Codec
    - bc：Bouncy Castle

+ Base64的应用场景：
    - e-mail
    - 密钥
    - 证书文件
+ Base64:
    - 定义：与64个字符的编码算法
    - RFC2045相关规范
    - 与加减密的关系
    
### 消息摘要算法加密
+ MD（Message Digest）
    - MD家族 128位摘要信息，特点：`摘要长度都是128`，`单向加密`
        * MD2 实现方：JDK
        * MD4 实现方：Bouncy Castle
        * MD5 实现方：JDK
    - cc（DigestUtils） 对jdk进行二次封装使用起来更加方便；bc 对jdk进行补充，用起来相对复杂一点
    - MD算法的应用
        * 用户注册时添加的密码
+ SHA（Secure Hash Algorithm） 安全散列算法，**固定长度**摘要信息的算法
    - 是在MD4的基础上衍生而来的
    
        算法|摘要长度|实现方
        ----|----|----
        SHA-1|160|JDK  
        SHA-2||
        SHA-224|225|Bouncy Castle
        SHA-256|256|JDK
        SHA-384|384|JDK
        SHA-512|512|JDK
    
    - SHA 算法应用
        * 消息发送方 -> 发布消息摘要算法 -> 接收方
        * 发送方对待发布消息进行摘要处理
        * 发送发发布摘要消息给接收方
        * 发送方发送消息给接收方
        * 接收方进行`消息鉴别`（在接收方将原始信息进行摘要，然后与接收到的摘要信息进行比对）
        
+ MAC (Message Authectication Code) 消息认证码算法， 包含了MD和SHA的消息摘要算法
    也叫 HMAC（keyed-Hash Message Authentication Code）含有密钥的散列函数算法
    - 融合MD SHA
        - MD系列：HmacMD、 HmacMD4、HmacMD5
        - SHA系列：HmacSHA1、HmacSHA224、HmacSHA256、HmacSHA384、HmacSHA512
    - 应用如SecureCRT，linux应用的客户端
    - mac摘要算法
        
        算法|摘要长度|实现方
        ---|---|---
        HmacMD|128|Bouncy Castle
        HmacMD4|128|Bouncy Castle
        HmacMD5|128|JDK
        HmacSHA1|160|JDK
        HmacSHA224|224|Bouncy Castle
        HmacSHA256|256|JDK
        HmacSHA384|384|JDK
        HmacSHA512|512|JDK
    
    - mac算法应用
        * 发送方发布消息摘要算法给接收方
        * 发送方构建密钥
        * 发送方发送密钥给接收方
        * 发送方对待发送消息进行摘要处理
        * 发送方发送消息摘要给接受方
        * 发送方发送消息给接收方
        * 接收方进行消息鉴别
        
+ 以上三种方法的作用：
    - 验证数据的完整性
    - 数字签名核心算法
    
+ 其他消息摘要算法
    - RipeMD
    - Tiger
    - Whirlpool
    - GOST3411
    
    
### 对称加密算法：加密密钥 = 解密密钥
+ 初等加密算法，安全性没有那么高
+ DES(Data Encryption Standard) 数据加密标准，（被不断破解，已经不安全了）
    
    密钥长度|默认|工作模式|填充方式|实现方
    ---|---|---|---|---
    56|56|ECB、CBC、PCBC、CTR、CTS、CFB、CFB8到128、OFB、OFB8到128|NoPadding、PKCS5Padding、ISO10126padding|JDK
    64|56|ECB、CBC、PCBC、CTR、CTS、CFB、CFB8到128、OFB、OFB8到128|PKCS7Padding、ISO10126d2Padding、X932Padding、ISO7816d4Padding、ZeroBytePadding|BC
    
    - 应用场景：
        * 发送方构建密钥
        * 发送发公布密钥给接收方
        * 发送方使用密钥对数据进行加密
        * 发送方发送加密数据给接收方
        * 接收方使用密钥对数据进行解密
        
    
+ 3DES（DES长度的加长版）实际应用多
    - 好处
        * 密钥长度增强
        * 迭代次数提高
    - 3DES（Triple DES 或 DESede）
        
        密钥长度|默认|工作模式|填充方式|实现方
        ---|---|---|---|---
        112、168|168|ECB、CBC、PCBC、CTR、CTS、CFB、CFB8到128、OFB、OFB8到128|NoPadding、PKCS5Padding、ISO10126padding|JDK
        128、192|168|ECB、CBC、PCBC、CTR、CTS、CFB、CFB8到128、OFB、OFB8到128|PKCS7Padding、ISO10126d2Padding、X932Padding、ISO7816d4Padding、ZeroBytePadding|BC
            
+ AES（Advanced Encryption Standard）
    - 通常用于移动通信系统加密以及基于SSH协议的软件，如SSH Client、SecureCRT
    - DES的算法有漏洞，3DES处理效率比较低
    - AES使用比3DES更多，暂未收到官方证明被破解的案例
    - 高级，DES的替代者 
        
        密钥长度|默认|工作模式|填充方式|实现方
        ---|---|---|---|---
        128、192、256|128|ECB、CBC、PCBC、CTR、CTS、CFB、CFB8到128、OFB、OFB8到128|NoPadding、PKCS5Padding、ISO10126padding|JDK（256位密钥需要获取无政策限制权限文件）
        128、192、256|128|ECB、CBC、PCBC、CTR、CTS、CFB、CFB8到128、OFB、OFB8到128|PKCS7Padding、ZeroBytePadding|BC
                   
    - 无政策限制权限文件是指：因为某些国家的进口管制限制，JAVA发布的运行环境包中的加解密有一定的限制
    - 应用和DES一样
    
+ PBE （Password Based Encrypytion）基于口令加密
    - **特殊**在`口令加盐`
    - 结合了消息摘要算法和对称加密算法的优点
    - 通过加盐提高安全性
    - 对已有算法的包装： 如DES AES， JDK和BC提供的实现
    - 常用的有 `PBEWithMD5AndDES` 
        
        算法|密钥长度|默认|工作模式|填充方式|实现
        ---|---|---|---|---|---
        PBEWithMD5AndDES|64|64|CBC|PKCS5Padding、PKCS7Padding、ISO10126Padding、AeroBytePadding|BC
        PBEWithMD5AndRC2|112|128
        PBEWithSHA1AndDES|64|64
        PBEWithSHA1AndRC2|128|128
        PBEWithSHAAndIDEA-CBC|128|128
        PBEWithSHAAnd2-KeyTripleDES-CBC|128|128
        PBEWithSHAAnd3-KeyTripleDES-CBC|192|192
        PBEWithSHAAnd128BitRC2-CBC|128|128
        PBEWithSHAAnd40BitRC2-CBC|40|40
        PBEWithSHAAnd128BitRC4|128|128
        PBEWithSHAAnd40BitRC4|40|40
        PBEWithSHAAndTwofish-CBC|256|256
        PBEWithMD5AndDES|56|56|CBC|PKCS5Padding|JDK
        PBEWithMD5AndTripleDES|112、168|168
        PBEWithSHA1AndDESede|112、168|168
        PBEWithSHA1AndRC2_40|40~1024(8倍数)|128
    - 应用方式
        * 发送方构建口令:SecretKeyFactory PBEKeySpec SecretKey
        * 发送方发布口令给接收方
        * 发布方构建盐：SecureRandom  generateSeed(字节数)
        * 发送方使用口令和盐进行加密
        * 发送方发送盐、加密数据给接收方：Cipher
        * 接收方使用口令、盐对数据解密
+ IDEA
    
    
### 非对称加密算法
+ 对称加密一旦密钥泄漏将极度不安全，这是对称加密带来的困扰。
+ DH （Diffie-Hellman）密钥交换算法
    - 构建本地密钥
    - 密钥
        
        密钥长度|默认|工作模式|填充方式|实现方
        ----|----|----|----|----
        512~1024（64倍数）|1024|无|无|JDK
        
    - 初始化发送方密钥
        * KeyPairGenerator  getInstance("DH"),两个参数一个是加密算法方式，另外一个参数是指定使用哪个提供方；来生成KeyPair
        * KeyPair  中可以得到公钥和私钥
        * PublicKey
    - 初始化接收方密钥
        * KeyFactory 生成密钥generatePublic(), generatePrivate()
        * X509EncodedKeySpec  根据ASN.1标准进行密钥编码，getEncoded(),编码字节
        * DHPublicKey  publicKey的具体形式
        * DHParameterSpec   参数
        * KeyPairGenerator
        * PrivateKey
    - 密钥构成
        * KeyAgreement : 提供密钥一致性（或密钥交换）协议的功能
        * SecretKey：秘密密钥，对称密钥，生成一个分组的密钥，类型安全的操作，父接口Key
        * KeyFactory
        * X509EncodedKeySpec
        * PublicKey
    - 加密、解密
        * Cipher  构成了JCE核心内容， getInstance("算法名称")获取实体，提供加解密提供方法
    - 应用
    - 初始化DH算法密钥对
        * 发送方构建发送方的密钥
        * 发送方公布发送方密钥
        * 接收方使用发送方密钥构建自己密钥
        * 接受方公布公钥
    - DH算法加密消息传递
        * 发送方本地密钥加密
        * 发送方发送加密消息
        * 接受方使用本地密钥解密消息
        
+ RSA-基于因子分解，世界上应用范围最广的加密算法，既能用于加密，也能用于数字签名
    - 基于DH，唯一广泛接受并实现
    - 数据加密&数字签名
    - 公钥加密、私钥解密
    - 私钥加密、公钥解密
    - 相对于DH性能比较慢
    - 基于大数因子分解
    - 实现方式
    
        密钥长度|默认|工作模式|填充方式|实现方
        ----|----|----|----|----
        512~65536（64整数倍）|1024|ECB|NoPadding、PKCS1Padding、OAEPWITHMD5AndMGF1Padding、OAEPWITHSHA1AndMGF1Padding、OAEPWITHSHA256AndMGF1Padding、OAEPWITHSHA384AndMGF1Padding、OAEPWITHSHA512AndMGF1Padding|JDK
        512~65536（64整数倍）|1024|NONE|NoPadding、PKCS1Padding、OAEPWITHMD5AndMGF1Padding、OAEPWITHSHA1AndMGF1Padding、OAEPWITHSHA256AndMGF1Padding、OAEPWITHSHA384AndMGF1Padding、OAEPWITHSHA512AndMGF1Padding、ISO9796-1Padding|BC
    
    - 应用
    > 私钥加密公钥解密过程
    
        * 发送方使用私钥对数据进行加密
        * 发送方发送加密数据给接收方
        * 接收方使用公钥解密数据
    
    > 公钥加密私钥解密过程
        
        * 发送方使用公钥对数据进行加密
        * 发送方发送加密数据给接收方
        * 接收方使用私钥解密数据
        
    - PCKS: The Public-Key Cryptography Standards公钥密码学标准
        * PKCS#1：定义RSA公开密钥算法加密和签名机制，主要用于组织PKCS#7中所描述的数字签名和数字信封[22]。
        * PKCS#3：定义Diffie-Hellman密钥交换协议[23]。
        * PKCS#5：描述一种利用从口令派生出来的安全密钥加密字符串的方法。使用MD2或MD5 从口令中派生密钥，并采用DES-CBC模式加密。主要用于加密从一个计算机传送到另一个计算机的私人密钥，不能用于加密消息[24]。
        * PKCS#6：描述了公钥证书的标准语法，主要描述X.509证书的扩展格式[25]。
        * PKCS#7：定义一种通用的消息语法，包括数字签名和加密等用于增强的加密机制，PKCS#7与PEM兼容，所以不需其他密码操作，就可以将加密的消息转换成PEM消息[26]。
        * PKCS#8：描述`私有密钥`信息格式，该信息包括公开密钥算法的私有密钥以及可选的属性集等[27]。
        * PKCS#9：定义一些用于PKCS#6证书扩展、PKCS#7数字签名和PKCS#8私钥加密信息的属性类型[28]。
        * PKCS#10：描述证书请求语法[29]。
        * PKCS#11：称为Cyptoki，定义了一套独立于技术的程序设计接口，用于智能卡和PCMCIA卡之类的加密设备[30]。
        * PKCS#12：描述个人信息交换语法标准。描述了将用户公钥、私钥、证书和其他相关信息打包的语法[31]。
        * PKCS#13：椭圆曲线密码体制标准[32]。
        * PKCS#14：伪随机数生成标准。
        * PKCS#15：密码令牌信息格式标准[33]。
        
    
+ ElGamal - 基于离散对数
    - 只提供公钥加密算法，私钥解密，是有BC提供的。
    - 使用
        
        密钥长度|默认|工作模式|填充方式|实现方
        ----|----|----|----|----
        160~16384（8整数倍）|1024|ECB、NONE|NoPadding、PKCS1Padding、OAEPWITHMD5AndMGF1Padding、OAEPWITHSHA1AndMGF1Padding、OAEPWITHSHA256AndMGF1Padding、OAEPWITHSHA384AndMGF1Padding、OAEPWITHSHA512AndMGF1Padding、ISO9796-1Padding|BC
    
    - 使用方式和rsa及其相近   
        * 接收方构建密钥对
        * 接收方公布密钥给发送方
        * 发送方使用公钥加密数据
        * 发送方发送加密数据
        * 接收方私钥解密数据

+ ECC（Elliptical Curve Cryptography） - 椭圆曲线加密
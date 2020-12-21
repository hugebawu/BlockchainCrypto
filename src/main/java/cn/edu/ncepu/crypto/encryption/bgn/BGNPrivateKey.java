package cn.edu.ncepu.crypto.encryption.bgn;/**
 * @author Baiji Hu
 * email: drbjhu@163.com
 * @date 2020/12/21 10:06
 */

import java.math.BigInteger;
import java.security.PrivateKey;

/**
 * @ClassName BGNPrivateKey
 * @Description This is a class for storing the private key (p) of BGN.
 * @Author Administrator
 * @Date 2020/12/21 10:06
 * @Version 1.0
 **/
public class BGNPrivateKey implements PrivateKey {

    private BigInteger p;

    public BGNPrivateKey(BigInteger p) {
        this.p = p;
    }

    public BigInteger getP() {
        return p;
    }

    /*
     * @description: Returns the standard algorithm name for this key.

     * @return: java.lang.String
     **/
    @Override
    public String getAlgorithm() {
        return "Boneh-Goh-Nissim";
    }

    /*
     * @description: Returns the name of the primary encoding format of this key, or null if
     * this key does not support encoding.

     * @return: java.lang.String
     * @throws:
     **/
    @Override
    public String getFormat() {
        return "NONE";
    }

    /*
     * @description: Returns the key in its primary encoding format, or null if this key does
     * not support encoding.
     * @return: new byte[0]
     * @throws:
     **/
    @Override
    public byte[] getEncoded() {
        return null;
    }
}

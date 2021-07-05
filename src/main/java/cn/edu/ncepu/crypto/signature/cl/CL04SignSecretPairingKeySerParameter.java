package cn.edu.ncepu.crypto.signature.cl;

import cn.edu.ncepu.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.ncepu.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * @author Baiji Hu
 * email: drbjhu@163.com
 * @date 2021/7/2 20:48
 *//*
 * @ClassName CL04SecretKeySerParameter
 * @Description serializable secret key for CL04
 * @Author Administrator
 * @Date 2021/7/2 20:48
 * @Version 1.0
 */
public class CL04SignSecretPairingKeySerParameter extends PairingKeySerParameter {

    private transient Element g;
    private final byte[] byteArrayG;
    private transient Element x;
    private final byte[] byteArrayX;
    private transient Element y;
    private final byte[] byteArrayY;
    private transient List<Element> z;
    private final byte[][] byteArrayZ;

    public Element getG() {
        return g;
    }

    public Element getX() {
        return x;
    }

    public Element getY() {
        return y;
    }

    public List<Element> getZ() {
        return z;
    }

    public CL04SignSecretPairingKeySerParameter(PairingParameters pairingParameters, Element g, Element x, Element y, Element... z) {
        super(true, pairingParameters);
        this.g = g.getImmutable();
        this.byteArrayG = this.g.toBytes();
        this.x = x.getImmutable();
        this.byteArrayX = this.x.toBytes();
        this.y = y.getImmutable();
        this.byteArrayY = this.y.toBytes();
        this.z = Arrays.asList(z);
        byte[][] byteArray = new byte[z.length][];
        for (int i = 0; i < z.length; i++) {
            byteArray[i] = z[i].toBytes();
        }
        /*Stream<byte[]> s = IntStream.range(0, z.length).mapToObj(i -> z[i].toBytes());
        this.byteArrayZ = s.toArray(byte[][]::new);*/
        this.byteArrayZ = IntStream.range(0, z.length).mapToObj(i -> z[i].toBytes()).toArray(byte[][]::new);
    }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof CL04SignSecretPairingKeySerParameter) {
            CL04SignSecretPairingKeySerParameter that = (CL04SignSecretPairingKeySerParameter) anObject;
            // Compare g
            if (!PairingUtils.isEqualElement(this.g, that.getG())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayG, that.byteArrayG)) {
                return false;
            }
            // Compare x
            if (!PairingUtils.isEqualElement(this.x, that.getX())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayX, that.byteArrayX)) {
                return false;
            }
            // Compare y
            if (!PairingUtils.isEqualElement(this.y, that.getY())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayY, that.byteArrayY)) {
                return false;
            }
            // Compare z List
            /*if (!this.z.stream().sorted().collect(Collectors.joining()).equals(that.z.stream().sorted().collect(Collectors.joining())))
                return false;*/
            if (!this.z.toString().equals(that.z.toString()))
                return false;
            for (int i = 0; i < byteArrayZ.length; i++) {
                if (!Arrays.equals(this.byteArrayZ[i], that.byteArrayZ[i])) {
                    return false;
                }
            }
            // Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }

    private void readObject(java.io.ObjectInputStream objectInputStream)
            throws java.io.IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.getParameters());
        this.g = pairing.getG1().newElementFromBytes(this.byteArrayG).getImmutable();
        this.x = pairing.getZr().newElementFromBytes(this.byteArrayX).getImmutable();
        this.y = pairing.getZr().newElementFromBytes(this.byteArrayY).getImmutable();
        this.z = IntStream.range(0, this.byteArrayZ.length).mapToObj(i -> pairing.getZr().newElementFromBytes(this.byteArrayZ[i]).getImmutable()).collect(Collectors.toList());
    }
}

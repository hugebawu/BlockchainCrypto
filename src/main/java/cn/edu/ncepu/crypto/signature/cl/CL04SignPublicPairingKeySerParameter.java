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
 * @date 2021/7/2 20:43
 *//*
 * @ClassName CL04PublicKeySerParameter
 * @Description serializable public key for CL04
 * @Author Administrator
 * @Date 2021/7/2 20:43
 * @Version 1.0
 */
public class CL04SignPublicPairingKeySerParameter extends PairingKeySerParameter {
    private transient Element g;
    private final byte[] byteArrayG;
    private transient Element gT;
    private final byte[] byteArrayGT;
    private transient Element X;
    private final byte[] byteArrayX;
    private transient Element Y;
    private final byte[] byteArrayY;
    private transient List<Element> Z;
    private final byte[][] byteArrayZ;
    private transient List<Element> W;
    private final byte[][] byteArrayW;

    public Element getG() {
        return g.duplicate();
    }

    public Element getgT() {
        return gT.duplicate();
    }

    public Element getX() {
        return X.duplicate();
    }

    public Element getY() {
        return Y.duplicate();
    }

    public List<Element> getZ() {
        return Z;
    }

    public List<Element> getW() {
        return W;
    }

    public CL04SignPublicPairingKeySerParameter(PairingParameters pairingParameters, Element g, Element gT, Element X, Element Y, List<Element> Z, List<Element> W) {
        super(false, pairingParameters);
        this.g = g.getImmutable();
        this.byteArrayG = this.g.toBytes();
        this.gT = gT.getImmutable();
        this.byteArrayGT = this.gT.toBytes();
        this.X = X.getImmutable();
        this.byteArrayX = this.X.toBytes();
        this.Y = Y.getImmutable();
        this.byteArrayY = this.Y.toBytes();
        this.Z = Z;
        this.byteArrayZ = IntStream.range(0, Z.size()).mapToObj(i -> Z.get(i).toBytes()).toArray(byte[][]::new);
        this.W = W;
        this.byteArrayW = IntStream.range(0, W.size()).mapToObj(i -> W.get(i).toBytes()).toArray(byte[][]::new);
    }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof CL04SignPublicPairingKeySerParameter) {
            CL04SignPublicPairingKeySerParameter that = (CL04SignPublicPairingKeySerParameter) anObject;
            // Compare g
            if (!PairingUtils.isEqualElement(this.g, that.getG())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayG, that.byteArrayG)) {
                return false;
            }
            // Compare gT
            if (!PairingUtils.isEqualElement(this.gT, that.getgT())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayGT, that.byteArrayGT)) {
                return false;
            }
            // Compare X
            if (!PairingUtils.isEqualElement(this.X, that.getX())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayX, that.byteArrayX)) {
                return false;
            }
            // Compare Y
            if (!PairingUtils.isEqualElement(this.Y, that.getY())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayY, that.byteArrayY)) {
                return false;
            }
            // Compare Z List
            if (!this.Z.toString().equals(that.Z.toString()))
                return false;
            for (int i = 0; i < byteArrayZ.length; i++) {
                if (!Arrays.equals(this.byteArrayZ[i], that.byteArrayZ[i])) {
                    return false;
                }
            }
            // Compare W List
            if (!this.W.toString().equals(that.W.toString()))
                return false;
            for (int i = 0; i < byteArrayW.length; i++) {
                if (!Arrays.equals(this.byteArrayW[i], that.byteArrayW[i])) {
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
        this.gT = pairing.getGT().newElementFromBytes(this.byteArrayGT).getImmutable();
        this.X = pairing.getG1().newElementFromBytes(this.byteArrayX).getImmutable();
        this.Y = pairing.getG1().newElementFromBytes(this.byteArrayY).getImmutable();
        this.Z = IntStream.range(0, this.byteArrayZ.length).mapToObj(i -> pairing.getG1().newElementFromBytes(this.byteArrayZ[i]).getImmutable()).collect(Collectors.toList());
        this.W = IntStream.range(0, this.byteArrayW.length).mapToObj(i -> pairing.getG1().newElementFromBytes(this.byteArrayW[i]).getImmutable()).collect(Collectors.toList());
    }
}

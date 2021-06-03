package cn.edu.ncepu.crypto.signature.cl.sign;

import cn.edu.ncepu.crypto.signature.cl.keygen.KeyPair;
import cn.edu.ncepu.crypto.signature.cl.keygen.PublicKey;
import cn.edu.ncepu.crypto.signature.cl.keygen.SecretKey;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.plaf.jpbc.field.z.ZrElement;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class Sign {

    /**
     * @description: sign a committed (secret) message
     * @param: commitment
     * @param: keys
     * @return: cn.edu.ncepu.crypto.signature.cl.sign.Signature
     * @throws:
     **/

    public static Signature sign(final Element commitment, final KeyPair keys) {
        final PublicKey pk = keys.getPk();
        final SecretKey sk = keys.getSk();
        final ZrElement alpha = (ZrElement) pk.getPairing().getZr().newRandomElement().getImmutable();
        final Element a = pk.getGenerator().powZn(alpha);
        final List<Element> A = sk.getZ().stream().map(a::powZn).collect(Collectors.toCollection(ArrayList::new));
        final Element b = a.powZn(sk.getY()).getImmutable();
        final List<Element> B = A.stream().map(Ai -> Ai.powZn(sk.getY())).collect(Collectors.toCollection(ArrayList::new));
        final ZrElement xTimesY = alpha.mul(sk.getX().mul(sk.getY()));
        final Element c = a.powZn(sk.getX()).mul(commitment.powZn(xTimesY)).getImmutable();

        return new Signature(a, b, c, A, B);
    }
}

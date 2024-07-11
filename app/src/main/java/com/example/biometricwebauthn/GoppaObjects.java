package com.example.biometricwebauthn;

import org.bouncycastle.pqc.legacy.math.linearalgebra.GF2Matrix;
import org.bouncycastle.pqc.legacy.math.linearalgebra.GF2mField;
import org.bouncycastle.pqc.legacy.math.linearalgebra.GoppaCode;
import org.bouncycastle.pqc.legacy.math.linearalgebra.Permutation;
import org.bouncycastle.pqc.legacy.math.linearalgebra.PolynomialGF2mSmallM;
import org.bouncycastle.pqc.legacy.math.linearalgebra.PolynomialRingGF2m;

import java.io.Serializable;
import java.security.SecureRandom;

public class GoppaObjects implements Serializable{


    private static final long serialVersionUID = 1L;

    Integer m;
    Integer t;
    private static Integer k;
    private static Integer n;
    private static SecureRandom random;
    private static GF2Matrix h;
    private static GF2mField field;
    private static PolynomialGF2mSmallM poly;
    private static GF2Matrix H;
    private static GF2Matrix g;
    private static Permutation p1;
    private static Permutation p2;
    private static Permutation p;
    private static Permutation pInv;
    private static GF2Matrix G;
    private static PolynomialRingGF2m ring;
    private static GF2Matrix[] matrixSandInverse;


    public GoppaObjects(Integer m, Integer t, byte[] seed) {

        this.m = 13; // El grado del campo GF(2^m)
        this.t = 128; // El grado del polinomio de Goppa

        this.random = new SecureRandom(seed);

        this.field = new GF2mField(m);
        this.poly = new PolynomialGF2mSmallM(field, t, PolynomialGF2mSmallM.RANDOM_IRREDUCIBLE_POLYNOMIAL, random);
        this.h = GoppaCode.createCanonicalCheckMatrix(field, poly);
        GoppaCode.MaMaPe mmp = GoppaCode.computeSystematicForm(h, random);

        GF2Matrix M = (GF2Matrix) mmp.getSecondMatrix();
        GF2Matrix S = mmp.getFirstMatrix();



        this.H = M.extendRightCompactForm();
        this.g = ((GF2Matrix) M.computeTranspose()).extendLeftCompactForm();

        this.n = g.getNumColumns();
        this.k = H.getNumColumns() - H.getNumRows();

        this.p1 = mmp.getPermutation();
        this.p2 = new Permutation(n,random);
        this.p = p1.rightMultiply(p2);
        this.pInv = p.computeInverse();

        this.matrixSandInverse = GF2Matrix
                .createRandomRegularMatrixAndItsInverse(k, random);

        this.G = (GF2Matrix) matrixSandInverse[0].rightMultiply(g.rightMultiply(p2));
    }

    public GF2Matrix getGEncode() {
        // Deveulve la matris G pero la que se usa para cifrar
        return G;
    }

    public Integer getK() {
        return k;
    }

    public Integer getN() {
        return n;
    }
    public Permutation getP1() {
        return p1;
    }
    public Permutation getP2() {
        return p2;
    }
    public Permutation getP() {
        return p;
    }
    public Permutation getPinv() {
        return pInv;
    }
    public GF2Matrix geth() {
        return h;
    }
    public PolynomialRingGF2m getRing() {
        return new PolynomialRingGF2m(field, getPoly());
    }
    public GF2mField getField() {
        return field;
    }
    public  PolynomialGF2mSmallM getPoly() {
        return poly;
    }
    public GF2Matrix getSInv() {
        return matrixSandInverse[1];
    }
}
package com.example.biometricwebauthn;

import android.content.Context;
import android.content.res.Resources;

import org.bouncycastle.pqc.legacy.math.linearalgebra.GF2Matrix;
import org.bouncycastle.pqc.legacy.math.linearalgebra.GF2mField;
import org.bouncycastle.pqc.legacy.math.linearalgebra.Permutation;
import org.bouncycastle.pqc.legacy.math.linearalgebra.PolynomialGF2mSmallM;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class GoppaObjectsFiles {
    // Es la misma clase que antes pero los objetos se construyen a partir de los binarios que hay en res/raw
    private final Resources resources;
    private byte[] Gencode;
    private byte[] hencode;
    private byte[] sInvencode;
    private byte[] pInvencode;
    private byte[] p1encode;
    private byte[] fieldencode;
    private byte[] polyencode;

    private final GF2Matrix gEncode;
    private final GF2Matrix h;
    private final GF2Matrix sInv;
    private final Permutation pInv;
    private final Permutation p1;
    private final GF2mField field;
    private final PolynomialGF2mSmallM poly;
    private final Integer n;
    private final Integer k;

    public GoppaObjectsFiles(Context context){

        this.resources = context.getResources();
        this.Gencode = loadByteArrayFromFile(resources, R.raw.gencode);
        this.hencode = loadByteArrayFromFile(resources, R.raw.hencode);
        this.sInvencode = loadByteArrayFromFile(resources, R.raw.sinvencode);
        this.pInvencode = loadByteArrayFromFile(resources, R.raw.pinvencode);
        this.p1encode = loadByteArrayFromFile(resources, R.raw.p1encode);
        this.fieldencode = loadByteArrayFromFile(resources, R.raw.fieldencode);
        this.polyencode = loadByteArrayFromFile(resources, R.raw.polyencode);

        this.gEncode = new GF2Matrix(Gencode);
        this.h = new GF2Matrix(hencode);
        this.sInv = new GF2Matrix(sInvencode);
        this.pInv = new Permutation(pInvencode);
        this.p1 = new Permutation(p1encode);
        this.field = new GF2mField(fieldencode);
        this.poly = new PolynomialGF2mSmallM(field, polyencode);
        this.n = 8192; // m = 13, t = 128
        this.k = 6528;

    }

    public GF2Matrix getGEncode() {
        return gEncode;
    }

    public GF2Matrix geth() {
        return h;
    }

    public GF2Matrix getSInv() {
        return sInv;
    }

    public Permutation getPinv() {
        return pInv;
    }

    public Permutation getP1() {
        return p1;
    }

    public GF2mField getField() {
        return field;
    }

    public PolynomialGF2mSmallM getPoly() {
        return poly;
    }

    public Integer getN() {
        return n;
    }

    public Integer getK() {
        return k;
    }
    private static byte[] loadByteArrayFromFile(Resources resources, int resourceId) {
        InputStream inputStream = null;
        ByteArrayOutputStream byteArrayOutputStream = null;

        try {
            inputStream = resources.openRawResource(resourceId);
            byteArrayOutputStream = new ByteArrayOutputStream();
            byte[] buffer = new byte[8388608];
            int length;

            while ((length = inputStream.read(buffer)) != -1) {
                byteArrayOutputStream.write(buffer, 0, length);
            }

            return byteArrayOutputStream.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        } finally {
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            if (byteArrayOutputStream != null) {
                try {
                    byteArrayOutputStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

}

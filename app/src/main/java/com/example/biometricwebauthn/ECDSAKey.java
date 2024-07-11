package com.example.biometricwebauthn;

import android.util.Log;

import org.bouncycastle.pqc.legacy.math.linearalgebra.GF2Matrix;
import org.bouncycastle.pqc.legacy.math.linearalgebra.GF2Vector;
import org.bouncycastle.pqc.legacy.math.linearalgebra.GoppaCode;
import org.bouncycastle.pqc.legacy.math.linearalgebra.PolynomialGF2mSmallM;
import org.bouncycastle.pqc.legacy.math.linearalgebra.PolynomialRingGF2m;
import org.bouncycastle.util.Arrays;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Random;

public class ECDSAKey {


    private static byte[] privKeyBORRAR;

    private static GoppaObjectsFiles goppa = Globales.goppaFiles;
    private static int n = goppa.getN();
    private static Integer k = goppa.getK();


    private static Integer longitud; // Aqui se almacena la longitud en bits de la clave, a la que se le añaden bits para llegar a k
    private static PublicKey publicKey;
    private static GF2Vector privateKey; // Se almacena el valor de la clave privada oculta
    //	private static int[] embedings = generarArray((int) k/2);
//	private static int[] password = generarArray((int) k/2);
    private static int[] embedings;
    private static byte[] password;
    //private static GF2Vector errores; //BORRARR


    public ECDSAKey(byte[] password, int[] embedings) {
        Log.d("FUNCIONA", "En el constructor de RSA");
        this.password = password;
        this.embedings = embedings;
        //assert globales.goppa!=null : "No estan cargadas las matrices de goppa";
        //this.errores =generaVectorError(this.password, embedings);
        crearClaves();

    }
    public int[] parseaCara(String cara) {
        // esta funcion es para parsear los embeding a un formato que operable, los devuelve en GF2Vector con el padding de 1s a la derecha
        String[] cara_s = cara.split(" ");
        int[] res = new int[cara_s.length];
        for(int i=0; i<cara_s.length;i++) {
            res[i] = Integer.parseInt(cara_s[i]);
        }
        return res;
    }

    public static int[] parseaContraseña(String input) {
        //Esta funcion recibe la contraseña y la parsea de forma que se pueda añadir al vector de error.
        try {
            // Obtener una instancia del algoritmo de hash SHA-512
            MessageDigest digest = MessageDigest.getInstance("SHA-512");

            // Calcular el hash de la entrada
            byte[] hashBytes = digest.digest(input.getBytes());

            // Convertir los bytes del hash a un array de bits
            int[] hashBits = byteArrayToIntArray(hashBytes);

            return hashBits;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            // Manejar el caso en que el algoritmo de hash no esté disponible
            return null;
        }

    }
    private static String printBytes(byte[] cad) {
        StringBuilder sb = new StringBuilder();
        for (byte b : cad) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }
    private static String printIntArr(int[] arr){
        StringBuilder sb = new StringBuilder();
        for(int i : arr){
            sb.append(i);
        }
        return sb.toString();
    }
    public static GF2Vector generaVectorError(byte[] password, int[] biometria) {
        int n = 8192; // Longitud del vector generado y longitud deseada del resultado

        // Generar el vector aleatorio de longitud 8192 usando el password como semilla
        byte[] auxPass = new byte[n / 8]; // 8192 bits / 8 = 1024 bytes
        try {
            long seed = byteArrayToLong(password);
            Random randomSeed1 = new Random(seed);
            randomSeed1.nextBytes(auxPass);
        } catch (Exception e) {
            e.printStackTrace();
        }
        Log.d("BYTES RANDOM PASSWD", printBytes(auxPass));
        Log.d("BIOMETRIA", printIntArr(biometria));
        // Convertir el byte array generado a un int array
        int[] auxInt = byteArrayToIntArray(auxPass);

        // Crear un nuevo array con padding de ceros a la izquierda para embeddings
        int[] paddedEmbeddings = new int[n];
        int ceros = n - biometria.length;
        System.arraycopy(biometria, 0, paddedEmbeddings, ceros, biometria.length);

        // Realizar la operación XOR entre los dos vectores
        int[] result = new int[n];
        for (int i = 0; i < n; i++) {
            result[i] = auxInt[i] ^ paddedEmbeddings[i];
        }

        // Convertir el resultado a GF2Vector y devolverlo
        return arrayToGF2Vector(result);
    }

    // Método auxiliar para convertir byte array a long
    private static long byteArrayToLong(byte[] byteArray) {
        long value = 0;
        for (int i = 0; i < Math.min(byteArray.length, 8); i++) {
            value = (value << 8) | (byteArray[i] & 0xFF);
        }
        return value;
    }

    private static boolean verifySignature(byte[] data, byte[] signatureBytes, PublicKey publicKey) throws Exception {
        // Crear un objeto Signature para la verificación
        Signature verificationSignature = Signature.getInstance("SHA256withECDSA");

        // Inicializar el objeto Signature con la clave pública
        verificationSignature.initVerify(publicKey);

        // Verificar la firma
        verificationSignature.update(data);
        return verificationSignature.verify(signatureBytes);
    }


    public static int[] generarArray(int longitud) {
        // Genera vector aleatorio de longitud
        int[] array = new int[longitud];
        Random random = new Random();
        for (int i = 0; i < longitud; i++) {
            array[i] = random.nextInt(2); // Genera un número aleatorio entre 0 y 1
        }
        return array;
    }

    private static GF2Vector codifica(GF2Vector msj, GF2Vector eUe) {
        int[] claveInt = gf2VectorToIntArray(msj);
        int[] aux = new int[k];
        longitud = claveInt.length;

        for(int i=0; i<longitud; i++) {
            aux[i]=claveInt[i];
        }
        GF2Vector vec=arrayToGF2Vector(aux);
        Log.d("ERROR EN LA ENCODE", eUe.toString());
        return (GF2Vector) goppa.getGEncode().leftMultiply(vec).add(eUe);
    }


    private static byte[] decodifica(GF2Vector cBe, byte[] hash_pswd, int[] biometria) throws Exception {
        GF2Vector eUv = generaVectorError(hash_pswd, biometria);
        Log.d("ERROR EN LA DECODE", eUv.toString());
        GF2Vector c = (GF2Vector) cBe.add(eUv);
        GF2Vector cPinv = (GF2Vector) c.multiply(goppa.getPinv());
        GF2Vector syndrome = (GF2Vector) goppa.geth().rightMultiply(cPinv);

        //        System.out.println("sindro me = "+syndrome.toString());
        PolynomialRingGF2m ring = new PolynomialRingGF2m(goppa.getField(), goppa.getPoly());
        PolynomialGF2mSmallM[] sqRoot = ring.getSquareRootMatrix();
        GF2Vector zPinv  = GoppaCode.syndromeDecode(syndrome, goppa.getField(), goppa.getPoly(), sqRoot);

//       System.out.println("Error decodificado = "+ z.toString());
        GF2Matrix sInv = goppa.getSInv();
        // Corrección del mensaje
        GF2Vector mSG = (GF2Vector) cPinv.add(zPinv);
        mSG = (GF2Vector)mSG.multiply(goppa.getP1());
        GF2Vector z = (GF2Vector)zPinv.multiply(goppa.getPinv().computeInverse()); // Este es el vector de error, con él haremos la segunda comprobacion de la biometría
        Log.d("PESO HAMMING Z", ""+z.getHammingWeight());
        GF2Vector mS = mSG.extractRightVector(k);
        GF2Vector mVec = (GF2Vector)sInv.leftMultiply(mS);


        //GF2Vector cara = z.extractRightVector(384); // 384 es lo que miden los embedding que se extraen
        //GF2Vector comprobacion = (GF2Vector) cara.add(arrayToGF2Vector(biometria));

       // GF2Vector xU = (GF2Vector) goppa.getGEncode().leftMultiply(mVec);
        //GF2Vector eUe = (GF2Vector) xU.add(cBe);
        //GF2Vector comprobacion = (GF2Vector) eUe.add(eUv);

        int umbral = z.getHammingWeight();
        Log.d("COMPROBACION UMBRAL", ""+umbral);
        try {
            if(umbral <68) {
                byte[] clave_byte = gf2VectorToByes(mVec);
                byte[] clave = Arrays.copyOf(clave_byte, longitud/8);
                Log.d("CLAVE CODE DECODE", printBytes(clave));

                return clave;
            }else {
                throw new Exception("No se ha verificado la biometría");
            }
        }catch(Exception e) {
            System.out.println(e.getMessage());
            throw new Exception("No se ha verificado la biometría");
        }
        //        return mVec;
    }
    private static GF2Vector addPadding(int[] vec, int n) {
        // devuelve el vector vec añadiendole un padding de 0s a la derecha hasta que su longitud sea n
        int[] paddVec = new int[n];
        System.arraycopy(vec, 0, paddVec, 0, vec.length);
        return arrayToGF2Vector(paddVec);
    }


    private static int[] gf2VectorToIntArray(GF2Vector vector) {

        int[] result = new int[vector.getLength()];
        for (int i = 0; i < vector.getLength(); i++) {
            result[i] = vector.getBit(i);
        }
        return result;
    }


    private static void crearClaves() {
        try {
            // Crear un generador de par de claves ECDSA
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");

            // Inicializar el generador con una curva elíptica (por ejemplo, secp256r1)
            keyPairGenerator.initialize(256); // La longitud de la clave se especifica en bits

            // Generar el par de claves
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            // Obtener la clave pública y privada del par
            publicKey = keyPair.getPublic();
            byte[] privKey = keyPair.getPrivate().getEncoded();
            //privKeyBORRAR= privKey;  //  BORRARR
            Log.d("CLAVE CODE ORIGINAL", printBytes(privKey));
//            privateKey = ocultaClavePrivada(bytesToGF2Vector(privKey));
            privateKey=codifica(bytesToGF2Vector(privKey), generaVectorError(password, embedings));

            Globales.getInstance().setPrivateKey(privateKey);
            Log.d("CLAVE PRIVADA", Globales.getInstance().getPrivateKey().toString());


        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    private static GF2Vector bytesToGF2Vector(byte[] arr) {
        // TODO Auto-generated method stub
        return arrayToGF2Vector(byteArrayToIntArray(arr));
    }

    private static byte[] gf2VectorToByes(GF2Vector vec) {
        return intArrayToByteArray(gf2VectorToIntArray(vec));
    }

    public static PublicKey getPublicKey() {
        return publicKey;
    }


    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            sb.append(String.format("%02X", bytes[i]));
        }
        return sb.toString();
    }
    public static int[] byteArrayToIntArray(byte[] byteArray) {
        int[] intArray = new int[byteArray.length * 8]; // Cada byte tiene 8 bits
        int index = 0;
        for (byte b : byteArray) {
            for (int i = 7; i >= 0; i--) {
                intArray[index++] = (b >> i) & 0x01; // Obtener el valor del bit en la posición i
            }
        }
        return intArray;
    }

    // Función para convertir un arreglo de enteros (donde cada entero representa los bits) a un arreglo de bytes
    public static byte[] intArrayToByteArray(int[] intArray) {
        byte[] byteArray = new byte[(intArray.length + 7) / 8]; // Calcular el tamaño del arreglo de bytes
        for (int i = 0; i < byteArray.length; i++) {
            int value = 0;
            for (int j = 0; j < 8; j++) {
                int bitIndex = i * 8 + j;
                if (bitIndex < intArray.length) {
                    value |= intArray[bitIndex] << (7 - j); // Establecer el valor del bit en la posición j
                }
            }
            byteArray[i] = (byte) value;
        }
        return byteArray;
    }



    public PublicKey getPublickey() {
//    	crearClaves();
        return publicKey;
    }

    private static GF2Vector arrayToGF2Vector(int[] array) {
        int length = array.length;
        GF2Vector vector = new GF2Vector(length);

        for (int i = 0; i < length; i++) {
            if (array[i] == 1) {
                vector.setBit(i); // Establecer el bit en la posición i si el valor en el array es 1
            }
        }

        return vector;
    }


    public static byte[] obtenerFirma(byte[] msj, byte[] hash_pswd, int[] biometria) throws Exception {
        // Este metodo sera accesible desde fuera, y devolverá el msj firmado con la clave privada
//    	GF2Vector emb = solicitaDatosBiometricos();

        return recuperaYFirma(msj, hash_pswd, biometria);
    }

    private static byte[] recuperaYFirma(byte[] msj, byte[] hash_pswd, int[] biometria) throws Exception {
        // En este método se recupera la clave, y se firma el challenge
        //GF2Vector errors = generaVectorError(hash_pswd, embedings); // CAMBIAR EL VECTOR DE ERRORESSSS
        byte[] res = null;
        KeyFactory keyFactory;
        if(Globales.getInstance().getPrivateKey() == null){
            throw new IllegalArgumentException("No se ha creado ninguna clave.");
        }

        try {
            keyFactory = KeyFactory.getInstance("EC");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodifica(Globales.getInstance().getPrivateKey(), hash_pswd, biometria));
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
            Signature signature = Signature.getInstance("SHA256withECDSA"); // Este es el algoritmo que usamos en webauthn
            signature.initSign(privateKey);
            signature.update(msj);
            res = signature.sign();
            Log.d("VALOR DE LA FIRMA", printBytes(res));
        }catch(InvalidKeySpecException e){
            Log.e("ERROR DECODING","No se ha verificado la contraseña");
            throw e;
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            Log.e("Error firmando", e.getMessage());
            throw e;
        }


        return res;
    }



}







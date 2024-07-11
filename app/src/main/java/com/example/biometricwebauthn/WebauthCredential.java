package com.example.biometricwebauthn;


import android.util.Base64;
import android.util.Log;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;

import org.json.JSONException;
import org.json.JSONObject;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

public class WebauthCredential {

    // en esta misma clase se podria gestionar la recepcion de las opciones de credencial y la generacion del mismo
    static String opc = "{\"rp\": {\"name\": \"Prueba de concepto TFG\", \"id\": \"localhost\"}, \"user\": {\"id\": \"5IotrddHt3gnIGJZssWXpzVkiDlpmHvQQL8TVSefx9dtaKejXAOvJVNLfM5edT_cHAxb4hcESCwOYZ2_h_wvyA\", \"name\": \"aaa\", \"displayName\": \"aaa\"}, \"challenge\": \"f3NyfS_PUMODR75aUiDwGU7UC6hBIwN_4Dy_uV5xcq2NpeJgO2Uzby9cNxk5SRva6030NwVIPwo8ACjsPqimGQ\", \"pubKeyCredParams\": [{\"type\": \"public-key\", \"alg\": -7}], \"timeout\": 60000, \"excludeCredentials\": [], \"authenticatorSelection\": {\"requireResidentKey\": false, \"userVerification\": \"discouraged\"}, \"attestation\": \"none\"}";
    // static String opcAut = "{\"challenge\": \"ydT4Zap1dpDiREIebAGqcIOwRT8GR1AUNSWbrWkNRjm6trtus1Kn6H2uaGd6IXhrrsBSLHVMx0Fr6aL5SfItTw\", \"timeout\": 60000, \"rpId\": \"localhost\", \"allowCredentials\": [], \"userVerification\": \"required\"}";

    private static JSONObject opcionesReg;
    private static JSONObject opcionesAut;
    private static byte[] rawIdCredential = generateUniqueId(32);  // MODIFICAR PARA QUE SEA ÚNICO EL CREDENCIAL ID
    private static byte[] passwd;
    public WebauthCredential(byte[] pass, String radio){
        Log.d("OBJETO WEB CRED", "Se ha creado el objeto wc");
        int[] embeddings = getEmbFromRadio(radio);
        this.passwd=pass;
        this.claves = new ECDSAKey(passwd, embeddings);
    }

    private static int[] getEmbFromRadio(String radio) {
        int[] res = null;


        if(radio.equals("Persona 1. Muestra 1")) res = Globales.getInstance().persona1_cara1;
        else if(radio.equals("Persona 1. Muestra 2")) res = Globales.getInstance().persona1_cara2;
        else if( radio.equals("Persona 2. Muestra 1")) res = Globales.getInstance().persona2_cara1;
        else if (radio.equals("Persona 2. Muestra 2") ) res = Globales.getInstance().persona2_cara2;


        return res;
    }

    private static ECDSAKey claves;

    public static void parserOpcionesReg(String opciones) {
        try {
            opcionesReg = new JSONObject(opciones);
        }catch(JSONException e){
            e.printStackTrace();
        }
    }

    public static String generarCredencialRegistro(JSONObject opciones) {

        try{
            PublicKey publicKey = claves.getPublickey();

            JSONObject res = new JSONObject();
            byte[] rawId = generateUniqueId(32);
            rawIdCredential=rawId;
            String id = bytesToHex(rawId);

            res.put("id", Base64.encodeToString(rawId, Base64.URL_SAFE | Base64.NO_WRAP)); // id aleatorio del credencial
            res.put("rawId", Base64.encodeToString(rawId, Base64.URL_SAFE | Base64.NO_WRAP)); // id aleatorio del credencial
            res.put("type", "public-key");

            JSONObject clientDataJSON = new JSONObject();
            clientDataJSON.put("type", "webauthn.create");
            clientDataJSON.put("challenge", opciones.get("challenge"));
            clientDataJSON.put("origin", "https://localhost:8888"); //Cambiar para producción
            clientDataJSON.put("crossOrigin", false);


            ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
            ECPoint ecPoint = ecPublicKey.getW();

            // Obtener los bytes de la coordenada X
            byte[] xCoord = ecPoint.getAffineX().toByteArray();
            // Obtener los bytes de la coordenada Y
            byte[] yCoord = ecPoint.getAffineY().toByteArray();

            ObjectMapper mapper = new ObjectMapper(new CBORFactory());
            //JSONObject coseKey = new JSONObject();
            Map<String, Object> coseKey = new HashMap<>();
            coseKey.put("1", 2);	// Alg: ECDSA (2)
            coseKey.put("3", -7);	// Crv: P-256 (-7)
            coseKey.put("-1", 1);	// Curve: P-256 (1)
            coseKey.put("-2", xCoord);
            coseKey.put("-3", yCoord);
            byte[] cborData = mapToCbor(coseKey);

            String cborDatos = bytesToHex(cborData);
            String cborCoseBien = "a5"+cborDatos.substring(2,cborDatos.length()-2); // cambiar el tipo de mapa a uno de longitud definida

            cborData = hexToBytes(cborCoseBien);

            int tamaño = 37+16+2+32; //tamaño en bytes que tiene el auth_bytes

            ByteBuffer authBytes = ByteBuffer.allocate(tamaño + cborData.length);
            authBytes.put(calcularHash(opciones.getJSONObject("rp").getString("id")));  // rp_id hash  32 bytes
            authBytes.put((byte) 0x5d);  // flags 1 byte
            authBytes.put((byte) 0x00); authBytes.position(37); // sign count, 4 bytes
            authBytes.put((byte) 0x00); authBytes.position(53); // aqui irian los datos del aaguid, como no tenemos atestacion, todo a 0
            authBytes.position(54); authBytes.put((byte) 0x20); // aqui va la longitud del credential id, como ocupa 2 bytes y se lee de izq a derecha, salto un byte
            authBytes.put(rawId);
            authBytes.put(cborData);

            JSONObject attestationObject = new JSONObject();
            attestationObject.put("fmt", "none");
            attestationObject.put("att_stmt", "{}");
            attestationObject.put("authData", Base64.encodeToString(authBytes.array(), Base64.URL_SAFE | Base64.NO_WRAP));

            JSONObject response = new JSONObject();
            response.put("attestationObject", Base64.encodeToString(mapToCbor(jsonObjectToMap(attestationObject)), Base64.URL_SAFE | Base64.NO_WRAP));
            response.put("clientDataJSON", Base64.encodeToString(clientDataJSON.toString().getBytes(), Base64.URL_SAFE | Base64.NO_WRAP));

            res.put("response", response);

            return res.toString();
        }catch(JSONException e){
            e.printStackTrace();
            Log.e("ERROR CREDENCIAL REG", e.toString());
        }catch(Exception e){
            e.printStackTrace();
            Log.e("Excepcion CRED REG", e.getMessage());
        }

        return null;
    }

    public static void parserOpcionesAut(String opc) {
        try{
            opcionesAut = new JSONObject(opc);
        }catch (JSONException e){
            e.printStackTrace();
        }
    }

    public static String generaCredencialAutenticacion(JSONObject opciones, byte[] hash_pswd, String radioSeleccionada) throws Exception {
//		 formato opciones login
//		{"challenge": "bkhX0AVSTyZV0vRo1dNPWFLDxBVye-d4UVGX-ouGaSmXVv5HyeiBOLq6emOlk6uX278gifpW2HwAcNg2aLJS1Q",
//		"timeout": 60000,
//		"rpId": "localhost",
//		"allowCredentials": [],
//		"userVerification": "required"}
        int[] embeddings = getEmbFromRadio(radioSeleccionada);
       try{
           JSONObject res = new JSONObject();
           byte[] rawId =rawIdCredential;// tiene que ser el mismo id que en el registro
           String id = bytesToHex(rawId);

           //res.put("id", id);
           res.put("id", Base64.encodeToString(rawId, Base64.URL_SAFE | Base64.NO_WRAP));
           res.put("rawId",  Base64.encodeToString(rawId, Base64.URL_SAFE | Base64.NO_WRAP));
           res.put("type", "public-key");

           JSONObject clientDataJSON = new JSONObject();
           clientDataJSON.put("type", "webauthn.get");
           clientDataJSON.put("challenge", opciones.get("challenge"));
           clientDataJSON.put("origin", "https://localhost:8888"); //Cambiar mas adelante
//		clientDataJSON.put("crossOrigin", false);

           ByteBuffer authBytes = ByteBuffer.allocate(37);  // Para la autenticacion solo se usan los 37 ytes obligatorios
           authBytes.put(calcularHash("localhost"));  // rp_id hash  32 bytes
           authBytes.put((byte) 0x1d);  // flags 1 byte
           authBytes.put((byte) 0x00); authBytes.position(37); // sign count, 4 bytes
           authBytes.flip(); // Se prepara el buffer para lectura

           byte[] authBytes_bytes = new byte[authBytes.remaining()];
           authBytes.get(authBytes_bytes); // Esto lee los bytes del buffer y los almacena en el byte[]

           byte[] sha256CDJ = calcularHash(clientDataJSON.toString());
           byte[] firmar = new byte[authBytes_bytes.length+sha256CDJ.length];
           for(int i=0;i<authBytes_bytes.length; i++) {
               firmar[i]=authBytes_bytes[i];
           }
           for(int i=0; i<sha256CDJ.length;i++) {
               firmar[authBytes_bytes.length + i] = sha256CDJ[i];
           }
           byte[] firma=ECDSAKey.obtenerFirma(firmar, hash_pswd, embeddings);


           JSONObject response = new JSONObject();
           response.put("clientDataJSON", Base64.encodeToString(clientDataJSON.toString().getBytes(), Base64.URL_SAFE | Base64.NO_WRAP));
           response.put("authenticatorData", Base64.encodeToString(authBytes_bytes, Base64.URL_SAFE | Base64.NO_WRAP));
           response.put("signature", Base64.encodeToString(firma, Base64.URL_SAFE | Base64.NO_WRAP));


           res.put("response", response);
           return res.toString();
       }catch(JSONException e){
           e.printStackTrace();
       }catch(Exception e){
           throw e;
       }
       return null;
    }

    public static byte[] generateUniqueId(int numBytes) {
        SecureRandom random = new SecureRandom();
        byte[] id = new byte[numBytes];
        random.nextBytes(id);
        return id;
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static String bytesToString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(b).append(" ");
        }
        return sb.toString();
    }
    public static byte[] calcularHash(String mensaje) {
        try {
            // Crear una instancia de MessageDigest para SHA-256
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            // Calcular el hash del mensaje
            return digest.digest(mensaje.getBytes());
        } catch (NoSuchAlgorithmException e) {
            // Manejar la excepción NoSuchAlgorithmException
            e.printStackTrace();
            return null; // O manejar de otra forma según sea necesario
        }
    }

    public static byte[] calcularHash(byte[] mensaje) {
        try {
            // Crear una instancia de MessageDigest para SHA-256
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            // Calcular el hash del mensaje
            return digest.digest(mensaje);
        } catch (NoSuchAlgorithmException e) {
            // Manejar la excepción NoSuchAlgorithmException
            e.printStackTrace();
            return null; // O manejar de otra forma según sea necesario
        }
    }

    private static byte[] mapToCbor(Map<String, Object> mapa) {
        byte[] cborData = null;
        ObjectMapper mapper = new ObjectMapper(new CBORFactory());

        try {
            cborData = mapper.writeValueAsBytes(mapa);

        } catch (JsonProcessingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return cborData;
    }
    public static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
    public static Map<String, Object> jsonObjectToMap(JSONObject jsonObject) throws JSONException {
        Map<String, Object> map = new HashMap<>();

        // Obtén las claves del JSONObject
        Iterator<String> keys = jsonObject.keys();

        // Itera sobre las claves y agrega los pares clave-valor al mapa
        while (keys.hasNext()) {
            String key = keys.next();
            Object value = jsonObject.get(key);
            map.put(key, value);
        }

        return map;
    }
}




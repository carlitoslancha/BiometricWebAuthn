package com.example.biometricwebauthn;

import static spark.Spark.before;
import static spark.Spark.options;
import static spark.Spark.post;
import static spark.Spark.stop;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.view.MenuItem;
import android.view.View;
import android.view.inputmethod.InputMethodManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.AppCompatButton;

import com.google.android.material.bottomnavigation.BottomNavigationView;
import com.google.android.material.floatingactionbutton.FloatingActionButton;
import com.google.android.material.navigation.NavigationBarView;

import org.json.JSONException;
import org.json.JSONObject;

import java.security.MessageDigest;
import com.example.biometricwebauthn.R;


public class ActivityRegistro extends AppCompatActivity {
    private BottomNavigationView bottomNavigationView;
    private Boolean mandar =false;

    private static final ActionHandler actionHandlerEnviarRegistro = new ActionHandler();
    private static final ActionHandler actionHandlerEnviarAutenticacion = new ActionHandler();
    private static final ActionHandler actionHandlerPasswordRegistro = new ActionHandler(); // Se para hasta q el usuario meta la contraseña y le de a generar
    private static final ActionHandler actionHandlerPasswordAutenticaion = new ActionHandler(); // Se para hasta q el usuario meta la contraseña y le de a generar

    private static RadioGroup radioGroupRegistro, radioGroupAutenticacion;
    private static EditText passwd;
    private TextView nameTextView, usernameTextView, rpIdNameTextView, countDownTextView;
    private LinearLayout loadingLayout;
    private LinearLayout cardLayoutRegistro, cardLayoutAutenticacion;



    protected void onDestroy() {

        super.onDestroy();
        stop();
    }
    protected void onCreate(Bundle savedInstancesState){
        super.onCreate(savedInstancesState);
        setContentView(R.layout.registro_activity);


        AppCompatButton aceptarBotonRegistro = findViewById(R.id.aceptarBotonRegistro);
        LinearLayout botonesLinearRegistro = findViewById(R.id.botonesLinearResgistro);
        LinearLayout linearPasswordRegistro = findViewById(R.id.linearPasswordRegistro);

        AppCompatButton aceptarBotonAutenticacion = findViewById(R.id.aceptarBotonAutenticacion);
        LinearLayout botonesLinearAutenticacion = findViewById(R.id.botonesLinearAuteticacion);
        LinearLayout linearPasswordAutenticacion = findViewById(R.id.linearPasswordAutenticacion);

        AppCompatButton enviarBotonRegistro = findViewById(R.id.enviarBotonRegistro);
        AppCompatButton generarBotonRegistro = findViewById(R.id.generarBotonRegistro);
        AppCompatButton enviarBotonAutenticacion = findViewById(R.id.enviarBotonAutenticacion);
        AppCompatButton generarBotonAutenticacion = findViewById(R.id.generarBotonAutenticacion);

        loadingLayout = findViewById(R.id.loadingLayout);
        cardLayoutRegistro = findViewById(R.id.cardLayoutRegistro);
        nameTextView = findViewById(R.id.nameTextView);
        usernameTextView = findViewById(R.id.usernameTextView);
        rpIdNameTextView = findViewById(R.id.rp_idNameTextView);
        countDownTextView = findViewById(R.id.countDownTextView);

        generarBotonRegistro.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                generarBotonRegistro.setVisibility(View.GONE);
                actionHandlerPasswordRegistro.userActionPerformed();
                enviarBotonRegistro.setVisibility(View.VISIBLE);
                closeKeyboard();
            }
        });
        generarBotonAutenticacion.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                generarBotonAutenticacion.setVisibility(View.GONE);
                actionHandlerPasswordAutenticaion.userActionPerformed();
                enviarBotonAutenticacion.setVisibility(View.VISIBLE);
                closeKeyboard();
            }
        });
        enviarBotonRegistro.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {

                actionHandlerEnviarRegistro.userActionPerformed();

            }
        });
        enviarBotonAutenticacion.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                actionHandlerEnviarAutenticacion.userActionPerformed();
            }
        });

        aceptarBotonRegistro.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                botonesLinearRegistro.setVisibility(View.GONE);
                linearPasswordRegistro.setVisibility(View.VISIBLE);

            }
        });
        aceptarBotonAutenticacion.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                botonesLinearAutenticacion.setVisibility(View.GONE);
                linearPasswordAutenticacion.setVisibility(View.VISIBLE);

            }
        });
        bottomNavigationView = findViewById(R.id.bottomNavigationView);
        bottomNavigationView.setOnItemSelectedListener(new NavigationBarView.OnItemSelectedListener() {
            @SuppressLint("NonConstantResourceId")
            @Override
            public boolean onNavigationItemSelected(@NonNull MenuItem item) {
                switch (item.getItemId()) {
                    case R.id.home:
                        Globales.server_running=false;
                        startActivity(new Intent(ActivityRegistro.this, MainActivity.class));
                        break;
                    case R.id.registro:
                        break;
                }
                return true;
            }
        });

        FloatingActionButton home_button = findViewById(R.id.home);
        home_button.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startActivity(new Intent(ActivityRegistro.this, MainActivity.class));
            }
        });

        if (Globales.server_running){
            server_running();
        }
        //init();


    }
    private void server_running(){
        Globales.server_running=true;

        options("/*",
                (request, response) -> {

                    String accessControlRequestHeaders = request
                            .headers("Access-Control-Request-Headers");
                    if (accessControlRequestHeaders != null) {
                        response.header("Access-Control-Allow-Headers",
                                accessControlRequestHeaders);
                    }

                    String accessControlRequestMethod = request
                            .headers("Access-Control-Request-Method");
                    if (accessControlRequestMethod != null) {
                        response.header("Access-Control-Allow-Methods",
                                accessControlRequestMethod);
                    }

                    return "OK";
                });
        before((request, response) -> {
            response.header("Access-Control-Allow-Origin", "*");
            response.header("Access-Control-Request-Method", "GET, POST, PUT, DELETE, OPTIONS");
            response.header("Access-Control-Allow-Headers", "Origin, Content-Type, Accept");
            response.type("application/json");
        });

        post("/credReg",  (req, res) -> {

            byte[] hash=null;
            try {
                String opciones = req.body();
                if (opciones.isEmpty()) {
                    Log.d("RESPONSE", "Cuerpo vacío recibido, probablemente una solicitud OPTIONS preflight");
                    res.status(204); // No Content
                    return "Respuesta Vacia";
                }
                final JSONObject json;
                String cred = null;
                try{
                    json = new JSONObject(opciones);
                    runOnUiThread(() -> cambiarLayoutRegistro(json)); // cambia el layout para mostrar la solicitud en pantalla

                    actionHandlerPasswordRegistro.waitForUserAction();
                    Log.d("EERROORR", "erroer");
                    MessageDigest digest = MessageDigest.getInstance("SHA-512");
                    radioGroupRegistro = findViewById(R.id.radioGroupRegistro);
                    int caraSeleccionada = radioGroupRegistro.getCheckedRadioButtonId();
                    RadioButton radio = findViewById(caraSeleccionada);
                    String radioString = radio.getText().toString();
                    passwd = findViewById(R.id.inputPasswordRegistro);
                    Log.d("CONTRASEÑA", passwd.getText().toString());

                    hash = digest.digest(passwd.getText().toString().getBytes());
                    WebauthCredential wc = new WebauthCredential(hash, radioString);
                    cred = wc.generarCredencialRegistro(json);
                    Log.d("VALOR CRED REG", cred.toString());
                }catch (JSONException e){
                    e.printStackTrace();
                    Log.e("ERROR DEL JSON", e.getMessage());
                }catch(Exception e){
                    e.printStackTrace();
                    Log.e("ERROR JSON", e.getMessage());
                }
                //Log.d("JSON", json.toString());


                actionHandlerEnviarRegistro.waitForUserAction();
                runOnUiThread(() -> resetLayoutRegistro());
              //  return "ESTA ES LA RESPUESTA DE LA APLICACIÓN. Para solicitudes POST";
                return cred;
            } catch (Exception e) {
                e.printStackTrace();  // Imprime en consola la pila de errores
                res.status(500);
                return "Error interno del servidor: " + e.toString();
            }


        });


        post("/opcionesLogin", (req, res) ->{
            Log.d("SERVER POST DESPUES", "Despues de entrar en POST");

            byte[] hash = null;
            Log.d("PRUEBA SERVER FNCIONA", "ENtrando");
            try {
                String opciones = req.body();
                if (opciones.isEmpty()) {
                    Log.d("RESPONSE", "Cuerpo vacío recibido, probablemente una solicitud OPTIONS preflight");
                    res.status(204); // No Content
                    return "Respuesta Vacia";
                }
                Log.d("RESPONSE", opciones);
                final JSONObject json;
                String cred = null;
                try{
                    //json = WebauthCredential.generarCredencialRegistro(opc);
                    json = new JSONObject(opciones);
                    runOnUiThread(() -> cambiarLayoutAutenticacion(json));
                    actionHandlerPasswordAutenticaion.waitForUserAction();
                    MessageDigest digest = MessageDigest.getInstance("SHA-512");

                    radioGroupAutenticacion = findViewById(R.id.radioGroupAutenticacion);
                    int caraSeleccionada = radioGroupAutenticacion.getCheckedRadioButtonId();
                    RadioButton radio = findViewById(caraSeleccionada);
                    String radioSeleccionada = radio.getText().toString();
                    passwd = findViewById(R.id.inputPasswordAutenticacion);
                    Log.d("CONTRASEÑA", passwd.getText().toString());
                    hash = digest.digest(passwd.getText().toString().getBytes());
                    //WebauthCredential wc = new WebauthCredential(hash);
                    cred = WebauthCredential.generaCredencialAutenticacion(json, hash, radioSeleccionada);
                    //enviar.setEnabled(true);
                    Log.d("VALOR CRED AUT", cred.toString());
                }catch (JSONException e){
                    e.printStackTrace();
                    Log.e("ERROR DEL JSON", e.getMessage());
                }catch(Exception e){
                    e.printStackTrace();
                }
                //Log.d("JSON", json.toString());


                actionHandlerEnviarAutenticacion.waitForUserAction();

                //  return "ESTA ES LA RESPUESTA DE LA APLICACIÓN. Para solicitudes POST";
                runOnUiThread(() -> resetLayoutAutenticacion());
                return cred;
            } catch (Exception e) {
                e.printStackTrace();  // Imprime en consola la pila de errores
                res.status(500);
                Toast.makeText(ActivityRegistro.this, "ERROR. No se ha verificado la biometría.", Toast.LENGTH_SHORT);

                return "Error interno del servidor: " + e.toString();
            }
        });
    }






    private void cambiarLayoutRegistro(final JSONObject opciones) {
        try {
            JSONObject rpObject = opciones.getJSONObject("rp");
            JSONObject userObject = opciones.getJSONObject("user");

            String rpName = rpObject.getString("name");
            String rpId = rpObject.getString("id");
            String userName = userObject.getString("name");
            String userDisplayName = userObject.getString("displayName");

            runOnUiThread(() -> {
                // Referencias a los elementos del layout de registro
                TextView tituloTV = findViewById(R.id.textViewTitulo);
                TextView nameTextView = findViewById(R.id.nameTextView);
                TextView usernameTextView = findViewById(R.id.usernameTextView);
                TextView rpIdNameTextView = findViewById(R.id.rp_idNameTextView);
                LinearLayout loadingLayout = findViewById(R.id.loadingLayout);
                LinearLayout cardLayoutRegistro = findViewById(R.id.cardLayoutRegistro);

                // Actualizar el texto del título
                tituloTV.setText("Solicitud de registro recibida: ");
                // Ocultar el indicador de carga
                loadingLayout.setVisibility(View.GONE);

                // Actualizar la información de la tarjeta
                nameTextView.setText(rpName);
                usernameTextView.setText("Username: " + userDisplayName);
                rpIdNameTextView.setText(userName);

                // Mostrar la tarjeta de registro
                cardLayoutRegistro.setVisibility(View.VISIBLE);
            });
            Log.d("CAMBIANDO CARD", "Se está cambiando la tarjeta de registro");
        } catch (JSONException e) {
            e.printStackTrace();
            Log.e("JSON_ERROR", "Fallo al cambiar la tarjeta de registro");
        }
    }
    private void cambiarLayoutAutenticacion(final JSONObject opciones) {
        try {
            //JSONObject rpObject = opciones.getJSONObject("rp");
           // JSONObject userObject = opciones.getJSONObject("user");

            //String rpName = rpObject.getString("name");
            //String rpId = rpObject.getString("id");
            //String userName = userObject.getString("name");
            //String userDisplayName = userObject.getString("displayName");

            runOnUiThread(() -> {
                // Referencias a los elementos del layout de autenticación
                TextView tituloTV = findViewById(R.id.textViewTituloAutenticacion);
                TextView nameTextView = findViewById(R.id.nameTextViewAutenticacion);
                TextView usernameTextView = findViewById(R.id.usernameTextViewAutenticacion);
                TextView rpIdNameTextView = findViewById(R.id.rp_idNameTextViewAutenticacion);
                LinearLayout loadingLayout = findViewById(R.id.loadingLayout);
                LinearLayout cardLayoutAutenticacion = findViewById(R.id.cardLayoutAutenticacion);

                // Actualizar el texto del título
                tituloTV.setText("Solicitud de autenticación recibida: ");
                // Ocultar el indicador de carga
                loadingLayout.setVisibility(View.GONE);

                // Actualizar la información de la tarjeta
                //nameTextView.setText(rpName);
                //usernameTextView.setText("Username: " + userDisplayName);
                //rpIdNameTextView.setText(userName);

                // Mostrar la tarjeta de autenticación
                cardLayoutAutenticacion.setVisibility(View.VISIBLE);
            });
            Log.d("CAMBIANDO CARD", "Se está cambiando la tarjeta de autenticación");
        } catch (Exception e) {
            e.printStackTrace();
            Log.e("JSON_ERROR", "Fallo al cambiar la tarjeta de autenticación");
        }
    }


    private void resetLayoutRegistro() {
        runOnUiThread(() -> {
            // Referencias a los elementos del layout de registro
            TextView tituloTV = findViewById(R.id.textViewTitulo);
            TextView nameTextView = findViewById(R.id.nameTextView);
            TextView usernameTextView = findViewById(R.id.usernameTextView);
            TextView rpIdNameTextView = findViewById(R.id.rp_idNameTextView);
            LinearLayout loadingLayout = findViewById(R.id.loadingLayout);
            LinearLayout cardLayoutRegistro = findViewById(R.id.cardLayoutRegistro);
            LinearLayout botonesLinearRegistro = findViewById(R.id.botonesLinearResgistro);
            LinearLayout linearPasswordRegistro = findViewById(R.id.linearPasswordRegistro);
            Button enviarBotonRegistro = findViewById(R.id.enviarBotonRegistro);

            // Restablecer la visibilidad y el contenido de los elementos
            loadingLayout.setVisibility(View.VISIBLE);
            cardLayoutRegistro.setVisibility(View.GONE);
            botonesLinearRegistro.setVisibility(View.VISIBLE);
            linearPasswordRegistro.setVisibility(View.VISIBLE);
            enviarBotonRegistro.setVisibility(View.VISIBLE);

            tituloTV.setText("Solicitud de registro recibida: ");
            nameTextView.setText("");
            usernameTextView.setText("Username: ");
            rpIdNameTextView.setText("");
        });
        Log.d("RESET LAYOUT", "Se ha restablecido el layout de registro");
    }
    private void resetLayoutAutenticacion() {
        runOnUiThread(() -> {
            // Referencias a los elementos del layout de autenticación
            TextView tituloTV = findViewById(R.id.textViewTituloAutenticacion);
            TextView nameTextView = findViewById(R.id.nameTextViewAutenticacion);
            TextView usernameTextView = findViewById(R.id.usernameTextViewAutenticacion);
            TextView rpIdNameTextView = findViewById(R.id.rp_idNameTextViewAutenticacion);
            LinearLayout loadingLayout = findViewById(R.id.loadingLayout);
            LinearLayout cardLayoutAutenticacion = findViewById(R.id.cardLayoutAutenticacion);
            LinearLayout botonesLinearAutenticacion = findViewById(R.id.botonesLinearAuteticacion);
            LinearLayout linearPasswordAutenticacion = findViewById(R.id.linearPasswordAutenticacion);
            Button enviarBotonAutenticacion = findViewById(R.id.enviarBotonAutenticacion);
            Button generarBotonAutenticacion = findViewById(R.id.generarBotonAutenticacion);

            // Restablecer la visibilidad y el contenido de los elementos
            loadingLayout.setVisibility(View.VISIBLE);
            cardLayoutAutenticacion.setVisibility(View.GONE);
            botonesLinearAutenticacion.setVisibility(View.VISIBLE);
            linearPasswordAutenticacion.setVisibility(View.GONE);
            enviarBotonAutenticacion.setVisibility(View.GONE);
            generarBotonAutenticacion.setVisibility(View.VISIBLE);

            tituloTV.setText("Solicitud de autenticación recibida: ");
            nameTextView.setText("");
            usernameTextView.setText("Username: ");
            rpIdNameTextView.setText("");
        });
        Log.d("RESET LAYOUT", "Se ha restablecido el layout de autenticación");
    }

    private void closeKeyboard() {
        View view = this.getCurrentFocus();
        if (view != null) {
            InputMethodManager imm = (InputMethodManager)getSystemService(Context.INPUT_METHOD_SERVICE);
            imm.hideSoftInputFromWindow(view.getWindowToken(), 0);
        }
    }

}

package com.example.biometricwebauthn;

import static spark.Spark.*;

import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CompoundButton;
import android.widget.ImageView;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.SwitchCompat;

import com.google.android.material.bottomnavigation.BottomNavigationView;
import com.google.android.material.navigation.NavigationBarView;

public class MainActivity extends AppCompatActivity {


    public static GoppaObjects goppa;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        if(Globales.getInstance().getPrivateKey() != null) {
            Log.d("VALOR CALVE PRIV MAIN", Globales.getInstance().getPrivateKey().toString());
        }
        SwitchCompat serverSwitch = findViewById(R.id.server_switch);
        ProgressBar progressBar = findViewById(R.id.progressGoppa);
        TextView textViewCargandoGoppa = findViewById(R.id.textViewCargandoGoppa);
        ImageView checkCircleIcon = findViewById(R.id.iconCheckGoppa);
        String directoryPath = this.getFilesDir().getAbsolutePath(); // Obtiene el directorio de archivos internos de la aplicación
        // File file = new File(directoryPath, FILE_NAME);
        //Log.d("FILE", file.getAbsolutePath());
        //Boolean bool = file.delete(); // BORRAR EL DELETE, NO ES PERSISTENTE

        Log.d("GOPPA == NULL", Globales.goppa==null?"true":"false");
        if(Globales.goppaFiles == null){
            new GoppaObjectsLoader(this, progressBar, new GoppaObjectsLoader.OnGoppaObjectsLoadedListener() {
                @Override
                public void onGoppaObjectsLoaded(GoppaObjectsFiles goppa) {
                    // Siempre crear el objeto GoppaObjects desde cero con una semilla específica
                    //goppa = new GoppaObjects(13, 128, globales.seed); // Asegúrate de que GoppaObjects acepta una semilla como tercer parámetro
                    Globales.goppaFiles = goppa;
                    // Mostrar un mensaje de éxito
                    Toast.makeText(MainActivity.this, "Objeto Goppa creado correctamente con semilla", Toast.LENGTH_SHORT).show();

                    // Ocultar la ProgressBar una vez que se haya completado la carga y actualizar la interfaz
                    int newWidthInDp = 35;
                    float scale = getResources().getDisplayMetrics().density;
                    int newWidthInPixels = (int) (newWidthInDp * scale + 0.5f);
                    ViewGroup.LayoutParams layoutParams = checkCircleIcon.getLayoutParams();
                    layoutParams.width = newWidthInPixels;
                    checkCircleIcon.setLayoutParams(layoutParams);
                    textViewCargandoGoppa.setText("Matrices de encriptación cargadas");
                    progressBar.setVisibility(View.GONE);
                    checkCircleIcon.setVisibility(View.VISIBLE);
                    serverSwitch.setEnabled(true);
                    Log.d("CREADO G", ""+Globales.goppaFiles.getGEncode().getNumColumns());
                }
            }).execute();
        }else{
            int newWidthInDp = 35;
            float scale = getResources().getDisplayMetrics().density;
            int newWidthInPixels = (int) (newWidthInDp * scale + 0.5f);
            ViewGroup.LayoutParams layoutParams = checkCircleIcon.getLayoutParams();
            layoutParams.width = newWidthInPixels;
            checkCircleIcon.setLayoutParams(layoutParams);
            textViewCargandoGoppa.setText("Matrices de encriptación cargadas");
            progressBar.setVisibility(View.GONE);
            checkCircleIcon.setVisibility(View.VISIBLE);
            serverSwitch.setEnabled(true);

        }

        if(Globales.server_running){
            serverSwitch.setChecked(true);
        }else{
            serverSwitch.setChecked(false);
        }
        serverSwitch.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                if (isChecked) {
                    // Si el switch está encendido, ejecuta la función arrancaServer()
                    Globales.server_running=true;
                } else {
                    // Si el switch está apagado, ejecuta la función apagaServer()
                    Globales.server_running=false;
                }
            }
        });

        BottomNavigationView bottomNavigationView = findViewById(R.id.bottomNavigationView);
        bottomNavigationView.setOnItemSelectedListener(new NavigationBarView.OnItemSelectedListener() {
            @Override
            public boolean onNavigationItemSelected(@NonNull MenuItem item) {
                switch (item.getItemId()) {
                    case R.id.home:
                        break;
                    case R.id.registro:
                        startActivity(new Intent(MainActivity.this, ActivityRegistro.class));
                        break;
                }
                return true;
            }
        });

    }



}
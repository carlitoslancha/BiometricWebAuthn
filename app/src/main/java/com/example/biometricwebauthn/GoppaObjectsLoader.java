package com.example.biometricwebauthn;

import android.content.Context;
import android.os.AsyncTask;
import android.view.View;
import android.widget.ProgressBar;

public class GoppaObjectsLoader extends AsyncTask<Void, Integer, GoppaObjectsFiles> {

    private Context mContext;
    private OnGoppaObjectsLoadedListener mListener;
    private ProgressBar mProgressBar;

    public GoppaObjectsLoader(Context context, ProgressBar progressBar, OnGoppaObjectsLoadedListener listener) {
        mContext = context;
        mProgressBar = progressBar;
        mListener = listener;
    }

    @Override
    protected void onPreExecute() {
        super.onPreExecute();
        if (mProgressBar != null) {
            mProgressBar.setVisibility(View.VISIBLE);
        }
    }

    @Override
    protected GoppaObjectsFiles doInBackground(Void... voids) {
        // Aquí creas el objeto GoppaObjects con una semilla especificada.
        // Asumiendo que la semilla se puede obtener desde una clase global o estáticamente
        GoppaObjectsFiles res;
        if (Globales.goppaFiles == null){
            res = new GoppaObjectsFiles(mContext);
        }else{res=Globales.goppaFiles;}

        return res;
    }

    @Override
    protected void onPostExecute(GoppaObjectsFiles goppa) {
        super.onPostExecute(goppa);
        if (mProgressBar != null) {
            mProgressBar.setVisibility(View.GONE);
        }
        if (mListener != null) {
            mListener.onGoppaObjectsLoaded(goppa);
        }
    }

    public interface OnGoppaObjectsLoadedListener {
        void onGoppaObjectsLoaded(GoppaObjectsFiles goppa);
    }
}

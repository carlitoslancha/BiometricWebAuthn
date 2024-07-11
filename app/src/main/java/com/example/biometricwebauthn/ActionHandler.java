package com.example.biometricwebauthn;
public class ActionHandler {
    private boolean ready = false;

    public synchronized void waitForUserAction() throws InterruptedException {
        ready=false;
        while (!ready) {
            wait(); // Esperar hasta que se notifique la acción del usuario
        }
    }

    public synchronized void userActionPerformed() {
        ready = true;
        notifyAll(); // Notificar a todos los hilos en espera que la acción del usuario está lista
    }
}

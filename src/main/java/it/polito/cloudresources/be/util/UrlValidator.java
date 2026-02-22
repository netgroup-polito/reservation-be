package it.polito.cloudresources.be.util;

import java.net.HttpURLConnection;
import java.net.URL;

public class UrlValidator {

    // Rimuoviamo la Regex complessa statica che causava l'ExceptionInInitializerError
    
    // Controllo Sintattico (Semplificato)
    public static boolean isValidSyntax(String urlString) {
        if (urlString == null || urlString.isBlank()) return false;
        
        // 1. Deve iniziare con http o https
        if (!urlString.toLowerCase().startsWith("http://") && !urlString.toLowerCase().startsWith("https://")) {
            return false;
        }

        // 2. Deve essere parsabile dalla classe URL di Java
        try {
            new URL(urlString).toURI();
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    // Controllo Fisico (Ping / Reachability)
    public static void checkUrlReachable(String urlString) {
        // Controllo sintassi base
        if (!isValidSyntax(urlString)) {
            throw new IllegalArgumentException("Formato URL non valido: deve iniziare con http:// o https://");
        }

        try {
            URL url = new URL(urlString);
            HttpURLConnection huc = (HttpURLConnection) url.openConnection();
            
            // Impostiamo un User-Agent generico per evitare che alcuni server ci blocchino pensando siamo un bot
            huc.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
            
            huc.setRequestMethod("HEAD"); // Scarica solo l'intestazione
            huc.setConnectTimeout(3000);  // 3 secondi max per connettersi
            huc.setReadTimeout(3000);
            
            int responseCode = huc.getResponseCode();

            // Accettiamo 200 (OK), 301/302 (Redirect)
            // Nota: Alcuni CDN restituiscono 403 o 405 sul metodo HEAD. Se vuoi essere più permissivo, accetta anche quelli.
            if (responseCode >= 400 && responseCode != 403 && responseCode != 405) {
                throw new IllegalArgumentException("URL irraggiungibile (Codice: " + responseCode + ")");
            }
        } catch (Exception e) {
            throw new IllegalArgumentException("Impossibile connettersi all'URL: " + e.getMessage());
        }
    }
}
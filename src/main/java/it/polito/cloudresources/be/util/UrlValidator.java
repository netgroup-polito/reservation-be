package it.polito.cloudresources.be.util;

import java.net.HttpURLConnection;
import java.net.URI; // AGGIUNGI QUESTO
import java.net.URL;

public class UrlValidator {

    // Controllo Sintattico (Moderno Java 21+)
    public static boolean isValidSyntax(String urlString) {
        if (urlString == null || urlString.isBlank()) return false;
        
        // 1. Deve iniziare con http o https
        if (!urlString.toLowerCase().startsWith("http://") && !urlString.toLowerCase().startsWith("https://")) {
            return false;
        }

        // 2. Parsabile dalla classe URI (Standard moderno)
        try {
            // Prima costruiamo l'URI (che valida la sintassi RFC 2396)
            // e poi lo convertiamo in URL (che valida il protocollo)
            new URI(urlString).toURL();
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    // Controllo Fisico (Ping / Reachability)
    public static void checkUrlReachable(String urlString) {
        if (!isValidSyntax(urlString)) {
            throw new IllegalArgumentException("Formato URL non valido: deve iniziare con http:// o https://");
        }

        try {
            // Usiamo il nuovo approccio anche qui
            URL url = new URI(urlString).toURL();
            HttpURLConnection huc = (HttpURLConnection) url.openConnection();
            
            // Impostiamo un User-Agent generico
            huc.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
            
            huc.setRequestMethod("HEAD");
            huc.setConnectTimeout(3000);
            huc.setReadTimeout(3000);
            
            int responseCode = huc.getResponseCode();

            // Accettiamo 200 (OK), 301/302 (Redirect), e scusiamo 403/405 (CDN restrittivi)
            if (responseCode >= 400 && responseCode != 403 && responseCode != 405) {
                throw new IllegalArgumentException("URL irraggiungibile (Codice: " + responseCode + ")");
            }
        } catch (Exception e) {
            throw new IllegalArgumentException("Impossibile connettersi all'URL: " + e.getMessage());
        }
    }
}
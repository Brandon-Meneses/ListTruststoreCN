import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class ListTruststoreCN {
    public static void main(String[] args) throws Exception {
        String truststorePath = "/Users/brandonluismenesessolorzano/Desktop/truststore.bks"; // Cambiar por tu archivo
        String password = "changeit"; // Cambiar por tu contraseña

        // Cargar el proveedor de Bouncy Castle
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        // Cargar el truststore
        KeyStore trustStore = KeyStore.getInstance("BKS", "BC");
        try (FileInputStream fis = new FileInputStream(truststorePath)) {
            trustStore.load(fis, password.toCharArray());
        }

        // Iterar sobre los certificados y extraer el CN
        Enumeration<String> aliases = trustStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            X509Certificate cert = (X509Certificate) trustStore.getCertificate(alias);

            if (cert != null) {
                String subject = cert.getSubjectX500Principal().getName();
                String cn = subject.replaceAll(".*CN=([^,]+).*", "$1"); // Extraer el CN
                System.out.println("Alias: " + alias + " | CN: " + cn);
            }
        }
    }
}

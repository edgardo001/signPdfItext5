/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package signpdfitext5;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.ExternalSignature;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;
import com.itextpdf.text.pdf.security.PrivateKeySignature;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author Datasoft
 */
public class SignPdfItext5 {

    /**
     * @param args the command line arguments
     * @throws java.security.KeyStoreException
     * @throws java.io.IOException
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.cert.CertificateException
     * @throws java.security.UnrecoverableKeyException
     */
    public static void main(String[] args) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException, DocumentException {
        try {
            signPdf();
        } catch (GeneralSecurityException ex) {
            Logger.getLogger(SignPdfItext5.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    //Pdf a firmar
    static File fpdfOrigen = new File("160KB Prueba - Test Standard.pdf");
    //nombre del pdf firmado
    static File fpdfDestino = new File("160KB Prueba - Test Standard-f.pdf");
    //certificado en formato p12 o pfx (debe contener llave privada, publica y certificado)
    static File fContenedorp12 = new File("myCertCreado.p12");
    //clave del p12 o pfx
    static String Contenedorp12clave ="Passw0rd";
    
    
    public static void signPdf() throws IOException, DocumentException, KeyStoreException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException, GeneralSecurityException {
        
        //Se agrega bouncyCastle al provider de java, si no se realiza, arroja un error
        Provider p = new BouncyCastleProvider();
        Security.addProvider(p);       
        
        //Se instancia un keystore de tipo pkcs12 para leer el contenedor p12 o pfx
        KeyStore ks = KeyStore.getInstance("pkcs12");
        //Se entrega la ruta y la clave del p12 o pfx
        ks.load(new FileInputStream(fContenedorp12.getAbsolutePath()), Contenedorp12clave.toCharArray());
        
        //Se obtiene el nombre del certificado
        String alias = (String)ks.aliases().nextElement();
        //Se obtiene la llave privada
        PrivateKey pk = (PrivateKey)ks.getKey(alias, Contenedorp12clave.toCharArray());
        //Se obtiene la cadena de certificados en base al nombre del certificado
        Certificate[] chain = ks.getCertificateChain(alias);
        //Se indica el origen del pdf a firmar
        PdfReader reader = new PdfReader(fpdfOrigen.getAbsolutePath());
        //Se indica el destino del pdf firmado
        PdfStamper stamper = PdfStamper.createSignature(reader, new FileOutputStream(fpdfDestino.getAbsolutePath()), '\0');
        //Se indican alguno detalles de la forma en que se firmara
        PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
        appearance.setReason("It's personal.");
        appearance.setLocation("Foobar");

        // Se entrega la llave privada del certificado, el algoritmo de firma y el provider usado (bouncycastle)
        ExternalSignature es = new PrivateKeySignature(pk, "SHA-256", "BC");
        ExternalDigest digest = new BouncyCastleDigest();

        //Se genera la firma y se almacena el pdf como se indico en las lineas anteriores
        MakeSignature.signDetached(appearance, digest, es, chain, null, null, null,0, CryptoStandard.CMS);
        
        //Se cierran las instancias para liberar espacio
        stamper.close();
        reader.close();          
    }
}


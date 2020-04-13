/*import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;

public class Fecha {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
     	Date date = new Date();
     	String toDay = dateFormat.format(date);
     	String fileName = "MILA810124" + "_" + "MILA810124J26" + "/" + "MILA810124J26" + "_" +  toDay + ".zip";
     	System.out.println("fileName:" + fileName);
	}

}*/
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.x509.X509V3CertificateGenerator;

public class Fecha {
  public static X509Certificate generateV3Certificate(KeyPair pair) throws InvalidKeyException,
      NoSuchProviderException, SignatureException {
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

    X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

    certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
    certGen.setIssuerDN(new X500Principal("CN=Test Certificate"));
    certGen.setNotBefore(new Date(System.currentTimeMillis() - 10000));
    certGen.setNotAfter(new Date(System.currentTimeMillis() + 10000));
    certGen.setSubjectDN(new X500Principal("CN=Test Certificate"));
    certGen.setPublicKey(pair.getPublic());
    certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

    certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
    certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature
        | KeyUsage.keyEncipherment));
    certGen.addExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(
        KeyPurposeId.id_kp_serverAuth));

    certGen.addExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(
        new GeneralName(GeneralName.rfc822Name, "test@test.test")));

    return certGen.generateX509Certificate(pair.getPrivate(), "BC");
  }

  public static void main(String[] args) throws Exception {
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    
    KeyPair pair;
    pair = generateRSAKeyPair();
    X509Certificate cert = generateV3Certificate(pair);
    cert.checkValidity(def);
    //cert.checkValidity(new Date());
    cert.verify(cert.getPublicKey());
  }
  public static KeyPair generateRSAKeyPair() throws Exception {
    KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
    kpGen.initialize(1024, new SecureRandom());
    return kpGen.generateKeyPair();
  }
}

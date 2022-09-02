package clienteSinSeguridad;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.util.Calendar;

import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Base64;

public class ProtocoloCliente {

	private static String identificacion;
	private static String localizacion;
	private static final String AES = "AES";
	private static final String BLOWFISH = "Blowfish";
	private static final String RSA = "RSA";
	private static final String HMACSHA1 = "HMACSHA1";
	private static final String HMACSHA256 = "HMACSHA256";
	private static final String HMACSHA384 = "HMACSHA384";
	private static final String HMACSHA512 = "HMACSHA512";
	private static KeyPair keyPair;
	private static Key llavePublicaServ;
	private static String algoritmoSimetrico = "";
	private static String algoritmoAsimetrico = "";

	public static void procesar(String inicio, BufferedReader pIn, PrintWriter pOut) throws IOException,
			NoSuchAlgorithmException, OperatorCreationException, CertificateException, ClassNotFoundException {

		// Lee del teclado
		System.out.println("Escriba el mensaje para enviar(HOLA para iniciar protocolo): ");
		String fromUser = inicio;

		// Envía por la red
		pOut.println(fromUser);

		String fromServer = "";

		// Lee lo que llega por la red
		if ((fromServer = pIn.readLine()) != null) {
			System.out.println("Respuesta del Servidor:" + fromServer);
		}

		// El usuario ingresa los datos para el servidor
		
		identificacion = Integer.toString((int) (Math.random() * 100) + 1);
		
		localizacion =Integer.toString((int) (Math.random() * 100) + 1);

		System.out.println("Ingrese identificacion: " + identificacion);
		System.out.println("Ingrese localizacion: " + localizacion);
		/*
		 * Inicia Etapa 1 El usuario selecciona los algoritmos para cifrar entre él y el
		 * servidor Cifrado simétrico, asimétrico y HMAC
		 */
		System.out.println("Seleccione que algoritmo dese usar \n Para Cifrado Simetrico \n 1) AES \n 2) BlOWFISH");

		String respuestaFinal = "ALGORITMOS:";

		int algSim = aleatorio();
		if (algSim == 1) {
			respuestaFinal = respuestaFinal + AES + ":" + RSA + ":";
			algoritmoSimetrico = AES;
			algoritmoAsimetrico = RSA;
		} else {
			respuestaFinal = respuestaFinal + BLOWFISH + ":" + RSA + ":";
			algoritmoSimetrico = BLOWFISH;
			algoritmoAsimetrico = RSA;

		}

		System.out.println(
				"Seleccione que algoritmo dese usar \n Para Cifrado HMAC \n 1) HmacSHA1 \n 2) HmacSHA256 \n 3) HmacSHA384 \n 4) HmacSHA512");

		int algHmac = (int) (Math.random() * 4) + 1;
		if (algHmac == 1) {
			respuestaFinal = respuestaFinal + HMACSHA1;
		} else if (algHmac == 2) {
			respuestaFinal = respuestaFinal + HMACSHA256;
		} else if (algHmac == 3) {
			respuestaFinal = respuestaFinal + HMACSHA384;

		} else if (algHmac == 4) {
			respuestaFinal = respuestaFinal + HMACSHA512;

		}

		// Recordar borrarlo
		System.out.println("Se envió: " + respuestaFinal);
		// Envia Algortimos que se van a usar
		pOut.println(respuestaFinal);

		// Lee lo que llega por la red dice si hubo un error o no en la entrada con
		// algotimos
		if ((fromServer = pIn.readLine()) != null) {
			System.out.println("Respuesta del Servidor:" + fromServer);
		}

		// Generar certificado de verificación del cliente
		generarLlave(RSA);// Generar llaves
		java.security.cert.X509Certificate certificado = gc(keyPair);
		byte[] certificadoEnBytes = certificado.getEncoded();
		String certificadoEnString = Base64.toBase64String(certificadoEnBytes);// Parse del certificado a String

		// Reccodar borrarlo
		System.out.println("Se envió: <CERTIFICADO> ");

		// Envia Cerificado que se van a usar
		pOut.println(certificadoEnString);

		// Lee lo que llega por la red, se recibio o no el certificado
		if ((fromServer = pIn.readLine()) != null) {
			System.out.println("Respuesta del Servidor:" + fromServer);
		}

		// Lee lo que llega por la red, corresponde al certificado
		if ((fromServer = pIn.readLine()) != null) {
			System.out.println("Respuesta del Servidor: <CERTIFICADO>");
		}

		// Se decodifica el certificado del cervidor y la llave publica
		byte[] certificadoServ = Base64.decode(fromServer);
		CertificateFactory cf = CertificateFactory.getInstance("X509");
		InputStream iS = new ByteArrayInputStream(certificadoServ);
		certificado = (X509Certificate) cf.generateCertificate(iS);
		llavePublicaServ = certificado.getPublicKey();

		if (llavePublicaServ != null) {
			// Recordar Borrar
			System.out.println("Se envió: OK");
			// Envian respuesta al servidor
			pOut.println("OK");
		} else {
			// Recordar Borrar
			System.out.println("Se envió: ERROR");
			// Envian respuesta al servidor
			pOut.println("ERROR");
		}

		// Inicia Etapa 2
		// Lee lo que llega por la red
		if ((fromServer = pIn.readLine()) != null) {
			System.out.println("Respuesta del Servidor: K_SC");
		}
		// Llave de cifrado simetrico
		byte[] llaveSC = Base64.decode(fromServer);

		// Lee lo que llega por la red
		if ((fromServer = pIn.readLine()) != null) {
			System.out.println("Respuesta del Servidor: <reto>");
		}
		// Reto

		System.out.println("Se envió: <reto>");
		pOut.println(fromServer);

		// Lee lo que llega por la red
		if ((fromServer = pIn.readLine()) != null) {
			System.out.println("Respuesta del Servidor:" + fromServer);
		}

		/*
		 * Inicia Etapa 3 Se cifra el id del Usuario que se pidió con la llava simetrica
		 */
		byte[] idUsuario = identificacion.getBytes();
		String idUsString = DatatypeConverter.printBase64Binary(idUsuario);
		System.out.println("Se envió: <" + identificacion + ">");
		pOut.println(idUsString);
		// Lee lo que llega por la red
		if ((fromServer = pIn.readLine()) != null) {
			System.out.println("Respuesta del Servidor <hhmm>");
		}
		// Descifrar la hora de respuesta del servidor asociada al id del usuario
		byte[] horadescifrada = Base64.decode(fromServer);

		String horaString = DatatypeConverter.printBase64Binary(horadescifrada);
		if (!horaString.isEmpty()) {

			System.out.println("Hora recibida: " + horaString.charAt(0) + horaString.charAt(1) + ":"
					+ horaString.charAt(2) + horaString.charAt(3));

			pOut.println("OK");

			System.out.println("Se envió: OK");

		} else {
			pOut.println("ERROR");
			System.out.println("Se envió: ERROR");
		}
	}

	// Método para generar llave basado en el algoritmo simetrico de tamaño 1024
	public static void generarLlave(String algoritm) throws NoSuchAlgorithmException {
		KeyPairGenerator generator = KeyPairGenerator.getInstance(algoritm);
		generator.initialize(1024);
		keyPair = generator.generateKeyPair();

	}

	public static X509Certificate gc(KeyPair keyPair) throws OperatorCreationException, CertificateException {
		Calendar endCalendar = Calendar.getInstance();
		endCalendar.add(Calendar.YEAR, 10);

		X509v3CertificateBuilder x509v3CertificateBuilder = new X509v3CertificateBuilder(new X500Name("CN=localhost"),
				BigInteger.valueOf(1), Calendar.getInstance().getTime(), endCalendar.getTime(),
				new X500Name("CN=localhost"), SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()));

		ContentSigner contentSigner = new JcaContentSignerBuilder("SHA1withRSA").build(keyPair.getPrivate());

		X509CertificateHolder x509CertificateHolder = x509v3CertificateBuilder.build(contentSigner);
		X509Certificate crt = (X509Certificate) (new JcaX509CertificateConverter()
				.setProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider())
				.getCertificate(x509CertificateHolder));
		return crt;
	}
	
	public static int aleatorio()
	{
		int numero = (int) (Math.random() * 10) + 1;
		if(numero%2==0)
		{
			return 1;
		}else {
			return 0;
		}
	}

}

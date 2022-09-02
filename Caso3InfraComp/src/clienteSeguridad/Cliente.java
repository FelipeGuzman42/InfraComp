package clienteSeguridad;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import org.bouncycastle.operator.OperatorCreationException;

public class Cliente {

	// -----------------------------------------------------------------
	// Constantes
	// -----------------------------------------------------------------

	public static final int PUERTO = 8080;

	public static final String SERVIDOR = "172.24.98.176";
	public static final String HOLA = "HOLA";
	public static final String ALGORITMOS = "ALGORITMOS";
	public static final String OK = "OK";
	public static final String ERROR = "ERROR";
	public static final String llave_publica="K_C";


	private boolean finEncuentro;


	public Cliente( )
	{
		finEncuentro = false;
	}


	public static void correr() throws IOException, NoSuchAlgorithmException, OperatorCreationException, CertificateException, ClassNotFoundException {

		Socket socket = null;
		PrintWriter escritor = null;
		BufferedReader lector =null;

		System.out.println("Cliente...");

		try {
			socket = new Socket(SERVIDOR,PUERTO);

			escritor =  new PrintWriter(socket.getOutputStream(),true);
			lector = new BufferedReader(new InputStreamReader(socket.getInputStream()));


		}catch(IOException e)
		{
			e.printStackTrace();
			System.exit(-1);
		}

		ProtocoloCliente.procesar(HOLA,lector,escritor);

		
		escritor.close();
		lector.close();
		socket.close();

	}


}




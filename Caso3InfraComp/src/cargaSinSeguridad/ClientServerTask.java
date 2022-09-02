package cargaSinSeguridad;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import org.bouncycastle.operator.OperatorCreationException;
import clienteSinSeguridad.Cliente;
import uniandes.gload.core.Task;

public class ClientServerTask extends Task{

	@Override
	public void execute() {

		try {
			Cliente.correr();
		} catch (NoSuchAlgorithmException | OperatorCreationException | CertificateException | ClassNotFoundException
				| IOException e) {
			e.printStackTrace();
		}
		
	}

	@Override
	public void fail() {
		// TODO Auto-generated method stub
		System.out.println(Task.MENSAJE_FAIL);
	}

	@Override
	public void success() {
		// TODO Auto-generated method stub
		System.out.println(Task.OK_MESSAGE);
	}
}

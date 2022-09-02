package project;

import java.io.BufferedReader;
import java.io.FileReader;

public class Principal {
	static Buffer buf;
	// Number of servers, clients, and messages to be initialised for the threads.
	static String numSer, numCli, numMen;

	public static void main(String[] args) {
		lectorArchivo();
		startClients();
		startServers();
	}

	// All servers are initialised here with the input of the counter starting from
	// 0, and the static buffer.
	public static void startServers() {
		if (Integer.parseInt(numSer) != 0) {
			for (int i = 0; i < Integer.parseInt(numSer); i++) {
				Thread t = new Servidor(Integer.toString(i), buf);
				t.start();
			}
		} else {
			System.out.println("No servers specified in file");
		}
	}

	// All clients are initialised here with the input of the counter starting from
	// 0, the number of messages and buffer.
	public static void startClients() {
		if (Integer.parseInt(numCli) != 0) {
			for (int i = 0; i < Integer.parseInt(numCli); i++) {
				Thread t = new Cliente(Integer.toString(i), numMen, buf);
				t.start();
			}
		} else {
			System.out.println("No clients specified in file");
		}
	}

	private static void lectorArchivo() {
		FileReader fr = null;
		BufferedReader br = null;
		String st, buffer = "";
		String[] a = new String[2];
		try {
			fr = new FileReader("./data/examplefile.txt");
			br = new BufferedReader(fr);
			while ((st = br.readLine()) != null) {
				a = st.split("=");
				switch (a[0]) {
				case "clientes":
					numCli = a[1];
					break;
				case "mensajes":
					numMen = a[1];
					break;
				case "servidores":
					numSer = a[1];
					break;
				case "tam_buffer":
					buffer = a[1];
					break;
				}
			}
			buf = new Buffer(buffer, numCli);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}

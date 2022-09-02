package project;

public class Servidor extends Thread {
	private int servidor_count = 0;
	private Mensaje men;
	private static Buffer br;
	private static boolean end = false;

	public Servidor(String contador, Buffer pBr) {
		servidor_count = Integer.parseInt(contador);
		br = pBr;
	}

	public void run() {
		System.out.println("Server number " + (this.servidor_count+=1) + " Started");
		while (!this.end) {
			men = br.receiveMessage(this);
			incrementer(men);
			br.returnMessage(men);
		}
		servidor_count--;
		if(servidor_count == 0) {
			System.out.println("Program finished");
		}
	}

	/**
	 * Incrementer
	 *
	 * @param men
	 * 
	 * gets the number stored in Mensaje class from the buffer,
	 * increments and updates in the mensaje class to be returned.
	 */
	public void incrementer(Mensaje men) {
		int temp;
		temp = men.getNumber();
		men.setNumber(++temp);
	}

	public static void setEnd() {
		end = true;
	}
}

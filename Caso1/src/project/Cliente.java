package project;

public class Cliente extends Thread {

	private static int cliente_count = 0;
	private int mensaje_count = 0;
	private static Buffer br;
	private Mensaje men;

	public Cliente(String contador, String mensaje, Buffer br1) {
		cliente_count = Integer.parseInt(contador);
		mensaje_count = Integer.parseInt(mensaje);
		br = br1;
	}

	public void run() {
		while(mensaje_count != 0) {
			men = new Mensaje();
			br.P(this);
			sendMessage();
			messageAnswered();
		}
		br.endCliente();
	}

	public void sendMessage() {
		System.out.println("Message: "+men.getNumber()+" sent!");
		br.sendMessage(men);
	}

	//The message is answered
	public void messageAnswered() {
		br.V(this);
		System.out.println("Message: "+men.getNumber()+" answered!");
		mensaje_count--;
	}
	
	public int getMensajes() {
		return mensaje_count;
	}

	public void setMensaje(int i) {
		mensaje_count = i;
	}

}

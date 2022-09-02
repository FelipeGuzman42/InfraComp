package project;

public class Mensaje {
	private int mensaje = 0;

	public Mensaje() {
		mensaje = (int) (Math.random() * 100+1);
	}

	public int getNumber() {
		return mensaje;
	}

	public void setNumber(int num) {
		this.mensaje = num;
	}
}

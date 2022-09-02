package project;

import java.util.ArrayList;

public class Buffer {
	private int buffer_count = 0;
	private final int totalMessage;
	private ArrayList<Mensaje> listaMensajes;
	private int numCliente = 0;

	public Buffer(String contador, String n) {
		buffer_count = Integer.parseInt(contador);
		totalMessage = buffer_count;
		listaMensajes = new ArrayList<>();
		numCliente = Integer.parseInt(n);
	}

	// Methods of the client

	/*
	 * Enter buffer
	 * 
	 * @param Cliente i If the buffer doesn't have space for messages, cliente
	 * yields
	 */
	public void P(Cliente i) {
		while (buffer_count <= 0) {
			i.yield();
		}
	}
	
	/* Leave buffer
	 * 
	 * @param Cliente i When cliente has finished its activity in buffer it
	 * increases the capacity of messages
	 */
	public synchronized void V(Cliente i) {
		buffer_count++;
	}

	/*
	 * S end message
	 * 
	 * @param Mensaje m Cliente sends a message to be operated by servidor 
	 * Buffer adds the message to listaMensajes and puts cliente to wait 
	 * inside the message.
	 */
	public void sendMessage(Mensaje m) {
		try {
			synchronized (m) {
				listaMensajes.add(m);
				buffer_count--;
				m.wait();
			}
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}


	/* endCliente
	 * 
	 * When cliente doesn't have more messages to send, it ends the thread and
	 * reduces the number of clientes
	 */
	public void endCliente() {
		synchronized (this) {
			numCliente--;
			System.out.println("Client satified");
		}
	}

	// Methods for servidor
	/*
	 * @param Servidor to end or yield
	 * 
	 * It checks if all clients have been satisfied, if not then checks if there
	 * are messages in listaMensajes, if there are, it removes the first and checks
	 * if it's null, if it is Servidor yields and keeps checking, if not, it sends it
	 * to operate internally.
	 * 
	 * @returns the message to operate
	 */
	public Mensaje receiveMessage(Servidor s) {
		synchronized (this) {
			if (numCliente == 0) {
				s.setEnd();
			}
			if(listaMensajes.isEmpty()) {
				Mensaje fin = new Mensaje();
				fin.setNumber(-1);
				return fin;
			}
			Mensaje m = listaMensajes.remove(0);
			while (m == null) {
				s.yield();
				if(listaMensajes.isEmpty()) {
					Mensaje fin = new Mensaje();
					fin.setNumber(-1);
					m = fin;
					break;
				}
				m = listaMensajes.remove(0);
			}
			return m;
		}
	}

	/*
	 * Notify cliente
	 * 
	 * @param Mensaje m Servidor returns the operated message to the cliente and
	 * notifies.
	 */
	public void returnMessage(Mensaje m) {
		synchronized (m) {
			m.notify();
		}
	}
}
package cargaConSeguridad;

import uniandes.gload.core.LoadGenerator;
import uniandes.gload.core.Task;

public class Generator {
	/**
	 * Load Generator Service (From GLoad 1.0)
	 */
	private LoadGenerator generator;
	
	/**
	 * Constructs a new Generator
	 */
	public Generator() {
		Task work = createTask();
		int numberOfTasks = 80;
		int gapBetweenTasks = 100;
		generator = new LoadGenerator("Client - Server Load Test", numberOfTasks, work, gapBetweenTasks);
		generator.generate();
	}
	
	/**
	 * Helper that Constructs a Task
	 */
	private Task createTask() {
		return new ClientServerTask();
	}
	/**
	 * Starts the Application
	 * @param args
	 */
	public static void main(String ...args) {
		@SuppressWarnings("unused")
		Generator gen = new Generator();
	}
}

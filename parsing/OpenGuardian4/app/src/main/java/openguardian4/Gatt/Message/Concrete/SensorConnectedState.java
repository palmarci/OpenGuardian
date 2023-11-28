package openguardian4.Gatt.Message.Concrete;

import openguardian4.Gatt.Message.AbstractGattMessage;

public class SensorConnectedState extends AbstractGattMessage {
	private final boolean connected;

	public SensorConnectedState(boolean connected) {
		this.connected = connected;
	}

	public boolean getConnected() {
		return this.connected;
	}

	public String toString() {
		return "SensorConnectedState{connected=" + this.connected + '}';
	}
}
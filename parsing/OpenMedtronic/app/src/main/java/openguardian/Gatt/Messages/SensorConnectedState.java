package openguardian.Gatt.Messages;

public class SensorConnectedState extends BaseMessage {
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
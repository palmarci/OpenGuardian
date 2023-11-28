package openguardian4.Gatt.Messages;

public class ConnectionActiveParams extends BaseMessage {
	public static final ConnectionActiveParams EMPTY = new ConnectionActiveParams(0, 0, 0, 0);
	private int connectionInterval;
	private int connectionSupervisionTimeOut;
	private int slaveLatency;
	private int updateSource;

	public ConnectionActiveParams(int updateSource, int connectionInterval, int slaveLatency,
			int connectionSupervisionTimeOut) {
		this.updateSource = updateSource;
		this.connectionInterval = connectionInterval;
		this.slaveLatency = slaveLatency;
		this.connectionSupervisionTimeOut = connectionSupervisionTimeOut;
	}

	public int getConnectionInterval() {
		return this.connectionInterval;
	}

	public int getConnectionSupervisionTimeOut() {
		return this.connectionSupervisionTimeOut;
	}

	public int getSlaveLatency() {
		return this.slaveLatency;
	}

	public int getUpdateSource() {
		return this.updateSource;
	}

	public String toString() {
		return "ConnectionActiveParams{updateSource=" + this.updateSource + ", connectionInterval="
				+ this.connectionInterval + ", slaveLatency=" + this.slaveLatency + ", connectionSupervisionTimeOut="
				+ this.connectionSupervisionTimeOut + '}';
	}
}
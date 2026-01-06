package openguardian4.Bluetooth;

public enum BtleMsgType {
	READ, NOTIFY, WRITE, INDICATE;

	public static BtleMsgType fromString(String value) {
		return BtleMsgType.valueOf(value.trim().toUpperCase());
	}

}
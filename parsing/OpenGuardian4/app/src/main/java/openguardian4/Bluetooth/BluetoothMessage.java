package openguardian4.Bluetooth;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.TimeZone;

import openguardian4.Utils;
import openguardian4.Gatt.ConverterMap;
import openguardian4.Gatt.GattPayload;
import openguardian4.Gatt.Messages.BaseMessage;

public class BluetoothMessage implements Comparable<BluetoothMessage> {

	private LocalDateTime time;
	private BluetoothMessageType type;
	private BaseMessage parsedMessage;
	private String service;
	private byte[] rawData;
	private boolean decrypted;

	public BluetoothMessage(long unixTimestamp, BluetoothMessageType type, String service, byte[] data,
			boolean decrypted) throws Exception {
		// parse unix timestamp
		this.time = LocalDateTime.ofInstant(Instant.ofEpochMilli(unixTimestamp), TimeZone.getDefault().toZoneId());
		this.type = type;
		// parse message if we have a converter for it
		var converter = ConverterMap.getConverter(service);

		if (converter != null) {
			this.parsedMessage = converter.unpack(new GattPayload(data));
		}

		this.service = service;
		// this.data = hexStringToByteArray(data);
		this.rawData = data;
		this.decrypted = decrypted;
	}

	public LocalDateTime getTime() {
		return this.time;
	}

	public void setTime(LocalDateTime time) {
		this.time = time;
	}

	public BluetoothMessageType getType() {
		return this.type;
	}

	public void setType(BluetoothMessageType type) {
		this.type = type;
	}

	public BaseMessage getParsedMessage() {
		return this.parsedMessage;
	}

	public void setParsedMessage(BaseMessage parsedMessage) {
		this.parsedMessage = parsedMessage;
	}

	public String getService() {
		return this.service;
	}

	public void setService(String service) {
		this.service = service;
	}

	public byte[] getRawData() {
		return this.rawData;
	}

	public void setRawData(byte[] rawData) {
		this.rawData = rawData;
	}

	public boolean isDecrypted() {
		return this.decrypted;
	}

	public boolean getDecrypted() {
		return this.decrypted;
	}

	public void setDecrypted(boolean decrypted) {
		this.decrypted = decrypted;
	}

	@Override
	public String toString() {
		return this.getClass() + " {" +
				" time='" + getTime() + "'" +
				", type='" + getType() + "'" +
				", parsedMessage='" + getParsedMessage() + "'" +
				", service='" + getService() + "'" +
				", rawData='" + Utils.bytesToHexStr(getRawData()) + "'" +
				", decrypted='" + isDecrypted() + "'" +
				"}";
	}

	@Override
	public int compareTo(BluetoothMessage another) {
		return this.time.compareTo(another.getTime());
	}

}

package openguardian4.Bluetooth;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.TimeZone;

import openguardian4.Utils;
import openguardian4.Gatt.Converters.UnpackException;
import openguardian4.Gatt.Message.AbstractGattMessage;
import openguardian4.Gatt.Message.GattPayload;

public class BluetoothMessage implements Comparable<BluetoothMessage> {

	private LocalDateTime time;
	private BluetoothMessageType type;
	private AbstractGattMessage parsedMessage;
	private String serviceUuid;
	private byte[] rawData;
	private boolean decrypted;

	public BluetoothMessage(long unixTimestamp, BluetoothMessageType type, String serviceUuid,
			byte[] data, boolean decrypted) {
		// parse unix timestamp
		var utcTime = LocalDateTime.ofInstant(Instant.ofEpochMilli(unixTimestamp),
				TimeZone.getTimeZone("Etc/UTC").toZoneId());
		var osTimeZone = TimeZone.getDefault().toZoneId();
		LocalDateTime currentTime = utcTime.atZone(TimeZone.getTimeZone("Etc/UTC").toZoneId())
				.withZoneSameInstant(osTimeZone).toLocalDateTime();
		this.time = currentTime;

		this.type = type;
		// parse message if we have a converter for it
		var converter = Utils.getConverter(serviceUuid);
		if (converter != null) {
			AbstractGattMessage unpacked = null;
			try {
				unpacked = converter.unpack(new GattPayload(data));
				this.parsedMessage = unpacked;

			} catch (UnpackException e) {
				System.err.println("Failed parsing payload: " + e);
			}
		}

		this.serviceUuid = serviceUuid;
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

	public AbstractGattMessage getParsedMessage() {
		return this.parsedMessage;
	}

	public void setParsedMessage(AbstractGattMessage parsedMessage) {
		this.parsedMessage = parsedMessage;
	}

	public String getServiceUuid() {
		return this.serviceUuid;
	}

	public void setServiceUuid(String serviceUuid) {
		this.serviceUuid = serviceUuid;
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
		return this.getClass().getSimpleName() + " {" + " time='" + getTime() + "'" + ", type='"
				+ getType() + "'" + ", parsedMessage='" + getParsedMessage() + "'"
				+ ", serviceUuid='" + getServiceUuid() + "'" + ", rawData='"
				+ Utils.bytesToHexStr(getRawData()) + "'" + ", decrypted='" + isDecrypted() + "'"
				+ "}";
	}

	@Override
	public int compareTo(BluetoothMessage another) {
		return this.time.compareTo(another.getTime());
	}

}

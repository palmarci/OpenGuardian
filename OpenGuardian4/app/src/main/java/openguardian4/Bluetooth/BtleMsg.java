package openguardian4.Bluetooth;

import openguardian4.Utils;
import openguardian4.Gatt.Converters.UnpackException;
import openguardian4.Gatt.Message.AbstractGattMessage;
import openguardian4.Gatt.Message.GattPayload;

public class BtleMsg {

	private int pcapNumber;
	private BtleDeviceType src;
	private BtleDeviceType dst;
	private BtleMsgType type;
	private AbstractGattMessage decodedMessage;
	private byte[] rawData;
	private String uuid;

	public BtleMsg(int pcapNumber, BtleDeviceType src, BtleDeviceType dst, BtleMsgType msgType, String uuid, byte[] data) {
		
		this.pcapNumber = pcapNumber;
		this.src = src;
		this.dst = dst;
		this.type = msgType;
		this.rawData = data;
		this.uuid = uuid;

		// parse message if we have a converter for it
		var converter = Utils.getConverter(uuid);
		if (converter != null) {
			AbstractGattMessage unpacked = null;
			try {
				unpacked = converter.unpack(new GattPayload(data));
				this.decodedMessage = unpacked;

			} catch (UnpackException e) {
				System.err.println("Failed parsing payload: " + e);
			}
		}
	}

	public BtleMsgType getType() {
		return this.type;
	}

	public void setType(BtleMsgType type) {
		this.type = type;
	}

	public AbstractGattMessage getDecodedMessage() {
		return this.decodedMessage;
	}

	public String getUUid() {
		return this.uuid;
	}

	public byte[] getRawData() {
		return this.rawData;
	}

	public int getPacketNumber() {
		return this.pcapNumber;
	}

	public BtleDeviceType getSource() {
		return this.src;
	}

	public BtleDeviceType getDestination() {
		return this.dst;
	}

	@Override
	public String toString() {
		return this.getClass().getSimpleName() + " {" +
				" pcapNumber='" + pcapNumber + "'" +
				", src='" + src + "'" +
				", dst='" + dst + "'" +
				", type='" + type + "'" +
				", parsedMessage='" + decodedMessage + "'" +
				", uuid='" + uuid + "'" +
				", rawData='" + Utils.bytesToHexStr(rawData) + "'" +
				"}";
	}

}

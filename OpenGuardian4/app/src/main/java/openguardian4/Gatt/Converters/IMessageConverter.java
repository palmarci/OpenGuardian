package openguardian4.Gatt.Converters;

import openguardian4.Gatt.Message.AbstractGattMessage;
import openguardian4.Gatt.Message.GattPayload;

public interface IMessageConverter {

//	public

	public AbstractGattMessage unpack(GattPayload gattPayload)throws UnpackException;
	public byte[] pack(AbstractGattMessage message) throws PackException;

//	public void printError(Exception e, Class<? extends AbstractMessageConverter> class1) {
//		System.err.println("Could not parse " + class1.getSimpleName() + ": " + e);
//	}

}

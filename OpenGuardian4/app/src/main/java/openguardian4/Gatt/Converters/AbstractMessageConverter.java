package openguardian4.Gatt.Converters;

import openguardian4.Gatt.Message.AbstractGattMessage;
import openguardian4.Gatt.Message.GattPayload;

public abstract class AbstractMessageConverter {

	public AbstractGattMessage unpack(GattPayload gattPayload) {
		return null;
	}

	public void printError(Exception e, Class<? extends AbstractMessageConverter> class1) {
		System.err.println("Could not parse " + class1.getSimpleName() + ": " + e);
	}

}

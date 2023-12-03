package openguardian4.Gatt.Converters.Concrete;

//import com.google.common.util.concurrent.ExecutionError;

import openguardian4.Gatt.Converters.AbstractMessageConverter;
//import openguardian4.Gatt.Converters.UnpackException;
import openguardian4.Gatt.Message.AbstractGattMessage;
import openguardian4.Gatt.Message.GattPayload;
import openguardian4.Gatt.Message.PayloadFormat;
import openguardian4.Gatt.Message.Concrete.ConnectionActiveParams;

public class ConnectionActiveParamsConverter extends AbstractMessageConverter {

	@Override
	public AbstractGattMessage unpack(GattPayload gattPayload) {

		try {
			int updateSource = gattPayload.unpackInt(PayloadFormat.FORMAT_UINT8.getValue(), 0);
			int offset = GattPayload.extractLowerNibble(PayloadFormat.FORMAT_UINT8.getValue()) + 0;

			int connectionInterval = gattPayload.unpackInt(PayloadFormat.FORMAT_UINT16.getValue(), offset);
			int offset2 = offset + GattPayload.extractLowerNibble(PayloadFormat.FORMAT_UINT16.getValue());

			int slaveLatency = gattPayload.unpackInt(PayloadFormat.FORMAT_UINT16.getValue(), offset2);
			int offset3 = offset2 + GattPayload.extractLowerNibble(PayloadFormat.FORMAT_UINT16.getValue());

			int connectionSupervisionTimeOut = gattPayload.unpackInt(PayloadFormat.FORMAT_UINT16.getValue(),
					offset3);

			// ChecksumVerifier.checkLength(gattPayload, offset3 + GattPayload.And15(18));
			// TODO
			return new ConnectionActiveParams(updateSource, connectionInterval, slaveLatency,
					connectionSupervisionTimeOut);
		} catch (Exception e) {
			super.printError(e, this.getClass());
			return null;
		}

	}

}

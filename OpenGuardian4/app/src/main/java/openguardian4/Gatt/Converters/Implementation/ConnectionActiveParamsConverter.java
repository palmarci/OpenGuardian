package openguardian4.Gatt.Converters.Implementation;

import openguardian4.Gatt.Converters.IMessageConverter;
import openguardian4.Gatt.Converters.PackException;
import openguardian4.Gatt.Converters.UnpackException;
//import openguardian4.Gatt.Converters.UnpackException;
import openguardian4.Gatt.Message.AbstractGattMessage;
import openguardian4.Gatt.Message.GattPayload;
import openguardian4.Gatt.Message.PayloadFormat;
import openguardian4.Gatt.Message.Implementation.ConnectionActiveParams;

public class ConnectionActiveParamsConverter implements IMessageConverter  {

	@Override
	public ConnectionActiveParams unpack(GattPayload gattPayload) throws UnpackException {

		//try {
			int updateSource = gattPayload.unpackInt(PayloadFormat.FORMAT_UINT8, 0);
			int offset = GattPayload.getNextLength(PayloadFormat.FORMAT_UINT8.getValue()) + 0;

			int connectionInterval = gattPayload.unpackInt(PayloadFormat.FORMAT_UINT16, offset);
			int offset2 = offset + GattPayload.getNextLength(PayloadFormat.FORMAT_UINT16.getValue());

			int slaveLatency = gattPayload.unpackInt(PayloadFormat.FORMAT_UINT16, offset2);
			int offset3 = offset2 + GattPayload.getNextLength(PayloadFormat.FORMAT_UINT16.getValue());

			int connectionSupervisionTimeOut = gattPayload.unpackInt(PayloadFormat.FORMAT_UINT16, offset3);

			// TODO: ChecksumVerifier.checkLength(gattPayload, offset3 + GattPayload.And15(18));
			return new ConnectionActiveParams(updateSource, connectionInterval, slaveLatency,
					connectionSupervisionTimeOut);
		//} catch (Exception e) {
	//		super.printError(e, this.getClass());
		//	return null;
	//	}

	}

	@Override
	public byte[] pack(AbstractGattMessage message) throws PackException {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Unimplemented method 'pack'");
	}

}

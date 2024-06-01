package openguardian4.Gatt.Converters.Implementation;

import openguardian4.RandomConstants;
import openguardian4.Gatt.Converters.IMessageConverter;
import openguardian4.Gatt.Converters.PackException;
import openguardian4.Gatt.Converters.UnpackException;
import openguardian4.Gatt.Enum.IntEnumConverter;
import openguardian4.Gatt.Enum.Implementation.SensorFeatures;
import openguardian4.Gatt.Message.AbstractGattMessage;
import openguardian4.Gatt.Message.GattPayload;
//import openguardian4.Gatt.Message.gattPayload;
import openguardian4.Gatt.Message.Implementation.CgmFeatures;
import openguardian4.Gatt.Message.PayloadFormat;

public class CgmFeaturesConverter implements IMessageConverter {

	@SuppressWarnings("unused") // crc
	public AbstractGattMessage unpack(GattPayload gattPayload) throws UnpackException {
		int crcValue = gattPayload.unpackInt(PayloadFormat.FORMAT_CRC_SOMETHING, 4);
		boolean deviceSupportsCrc = 65535 != crcValue;
		
		/* TODO: crc
		if (deviceSupportsCrc) {
			ChecksumVerifier.do_e2e_crc(gattPayload, 0, 4, 4);
		}
		*/

		int e2eCrcFeatureFlag = gattPayload.unpackInt(PayloadFormat.FORMAT_UINT32, 0) & RandomConstants.MEASURED_SIZE_MASK.getValue();
		int getNextLength = (GattPayload.getNextLength(PayloadFormat.FORMAT_UINT8.getValue()) * 3); //+ 0;
		int unpackInt = gattPayload.unpackInt(PayloadFormat.FORMAT_UINT8, getNextLength) & 15;
		int unpackInt2 = (gattPayload.unpackInt(PayloadFormat.FORMAT_UINT8, getNextLength) & RandomConstants.VIDEO_STREAM_MASK.getValue()) >> 4;
		int getNextLength2 = getNextLength + GattPayload.getNextLength(PayloadFormat.FORMAT_UINT8.getValue());
		if (!(deviceSupportsCrc ^ IntEnumConverter.fromInt(e2eCrcFeatureFlag, SensorFeatures.values()).contains(SensorFeatures.E2E_CRC))) {
			
			//TODO: crc ChecksumVerifier.checkLength(gattPayload, getNextLength2 + GattPayload.getNextLength(18));
			return new CgmFeatures(e2eCrcFeatureFlag, unpackInt, unpackInt2);
		}
		throw new UnpackException("Mismatch between CRC value (" + crcValue + ") and E2E-CRC feature flag (" + e2eCrcFeatureFlag + ")");
	}

	@Override
	public byte[] pack(AbstractGattMessage message) throws PackException {
		// TODO: Auto-generated method stub
		throw new UnsupportedOperationException("Unimplemented method 'pack'");
	}
}

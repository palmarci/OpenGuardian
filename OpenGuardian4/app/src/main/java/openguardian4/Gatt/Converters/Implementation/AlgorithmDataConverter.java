package openguardian4.Gatt.Converters.Implementation;

import openguardian4.Gatt.Converters.IMessageConverter;
import openguardian4.Gatt.Converters.UnpackException;
//import openguardian4.Gatt.Converters.UnpackException;
import openguardian4.Gatt.Enum.IntEnumConverter;
import openguardian4.Gatt.Enum.Implementation.AlgorithmDataFlags;
import openguardian4.Gatt.Message.AbstractGattMessage;
import openguardian4.Gatt.Message.GattPayload;
import openguardian4.Gatt.Message.PayloadFormat;
import openguardian4.Gatt.Message.Implementation.AlgorithmData;

import java.util.Set;

public class AlgorithmDataConverter implements IMessageConverter {

	@Override 
	public AlgorithmData unpack(GattPayload gattPayload) throws UnpackException {
		//try {
			Integer sensorError;
			Integer changeSensorError;
			Integer flags_raw = gattPayload.unpackInt(PayloadFormat.FORMAT_UINT8, 0);
			Integer offset = GattPayload.getNextLength(PayloadFormat.FORMAT_UINT8.getValue()) + 0; // TODO: offset weird?
																										
			Set<AlgorithmDataFlags> flags = IntEnumConverter.fromInt(flags_raw, AlgorithmDataFlags.values());
			if (flags.contains(AlgorithmDataFlags.SENSOR_ERROR_REASON_PRESENT)) {
				sensorError = gattPayload.unpackInt(PayloadFormat.FORMAT_UINT16, offset);
				offset += GattPayload.getNextLength(PayloadFormat.FORMAT_UINT16.getValue()); 
			} else {
				sensorError = 0;
			}
			if (flags.contains(AlgorithmDataFlags.CHANGE_SENSOR_ERROR_REASON_PRESENT)) {
				changeSensorError = gattPayload.unpackInt(PayloadFormat.FORMAT_UINT16, offset);
				offset += GattPayload.getNextLength(PayloadFormat.FORMAT_UINT16.getValue()); 
			} else {
				changeSensorError = 0;
			}
			/*
			 * TODO: get sensor features + check crc
			 * if (m4281d().m4226a().contains(EnumC7481c.E2E_CRC)) {
			 * extractLowerNibble += ChecksumVerifier.do_e2e_crc(gattPayload, 0, offset,
			 * offset);
			 * }
			 * ChecksumVerifier.checkLength(gattPayload, extractLowerNibble);
			 */
			// if (flags_raw != null && sensorError != null && changeSensorError)
			return new AlgorithmData(flags_raw, sensorError, changeSensorError);
		//} catch (Exception e) {
		//	super.printError(e, this.getClass());
		//	return null;
		//}
	}

	@Override
	public byte[] pack(AbstractGattMessage message) {
		// TODO: Auto-generated method stub
		throw new UnsupportedOperationException("Unimplemented method 'pack'");
	}
}
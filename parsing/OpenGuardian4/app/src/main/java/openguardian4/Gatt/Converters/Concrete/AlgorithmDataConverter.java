package openguardian4.Gatt.Converters.Concrete;

import openguardian4.Gatt.Converters.AbstractMessageConverter;
//import openguardian4.Gatt.Converters.UnpackException;
import openguardian4.Gatt.Enum.IntEnumConverter;
import openguardian4.Gatt.Message.Concrete.AlgorithmData;
import openguardian4.Gatt.Message.GattPayload;
import openguardian4.Gatt.Message.PayloadFormat;
import openguardian4.Gatt.Enum.Concrete.AlgorithmDataFlags;

import java.util.Set;

public class AlgorithmDataConverter extends AbstractMessageConverter {

	@Override // p123e.p416g.p471f.p472a.p502e.p503a.AbstractConverter,
			  // p123e.p416g.p471f.p472a.p502e.p503a.IDataConverter
	/* renamed from: k */
	/* renamed from: k */
	public AlgorithmData unpack(GattPayload gattPayload) {
		try {
			Integer sensorError;
			Integer changeSensorError;
			Integer flags_raw = gattPayload.unpackInt(PayloadFormat.FORMAT_UINT8.getValue(), 0);
			Integer offset = GattPayload.extractLowerNibble(PayloadFormat.FORMAT_UINT8.getValue()) + 0; // TODO offset weird?
																										
			Set<AlgorithmDataFlags> flags = IntEnumConverter.fromInt(flags_raw, AlgorithmDataFlags.values());
			if (flags.contains(AlgorithmDataFlags.SENSOR_ERROR_REASON_PRESENT)) {
				sensorError = gattPayload.unpackInt(PayloadFormat.FORMAT_UINT16.getValue(), offset);
				offset += GattPayload.extractLowerNibble(PayloadFormat.FORMAT_UINT16.getValue()); 
			} else {
				sensorError = 0;
			}
			if (flags.contains(AlgorithmDataFlags.CHANGE_SENSOR_ERROR_REASON_PRESENT)) {
				changeSensorError = gattPayload.unpackInt(PayloadFormat.FORMAT_UINT16.getValue(), offset);
				offset += GattPayload.extractLowerNibble(PayloadFormat.FORMAT_UINT16.getValue()); 
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
		} catch (Exception e) {
			super.printError(e, this.getClass());
			return null;
		}
	}
}
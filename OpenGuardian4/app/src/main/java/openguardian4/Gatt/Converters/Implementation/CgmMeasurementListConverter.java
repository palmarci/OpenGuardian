package openguardian4.Gatt.Converters.Implementation;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import openguardian4.Gatt.Converters.IMessageConverter;
import openguardian4.Gatt.Converters.PackException;
import openguardian4.Gatt.Converters.UnpackException;
import openguardian4.Gatt.Enum.IntEnumConverter;
import openguardian4.Gatt.Enum.Implementation.CgmMeasurementFlags;
import openguardian4.Gatt.Message.AbstractGattMessage;
import openguardian4.Gatt.Message.GattPayload;
import openguardian4.Gatt.Message.PayloadFormat;
import openguardian4.Gatt.Message.Implementation.CgmMeasurement;
import openguardian4.Gatt.Message.Implementation.CgmMeasurementList;

public class CgmMeasurementListConverter implements IMessageConverter {

    /*
     * private static class PayloadListHelper {
     * public final List<CgmMeasurement> cgmMeasurements = new
     * ArrayList<CgmMeasurement>();
     * public int offset = 0; //?
     * public final GattPayload payload;
     * 
     * public PayloadListHelper(GattPayload gattPayload) {
     * this.payload = gattPayload;
     * }
     * }
     */

    /* renamed from: k */
    @SuppressWarnings("unused") // for the CRC stuff
    public final CgmMeasurementList unpack(GattPayload payload) throws UnpackException {
        List<CgmMeasurement> measurements = new ArrayList<CgmMeasurement>();
        var payloadLength = payload.getCopy().length;

        int extractedCount = 0;
        while (extractedCount < payloadLength) {

            int i;
            int i2;
            Float f;
            Float f2;
            int unpackInt = payload.unpackInt(PayloadFormat.FORMAT_UINT8, extractedCount);
            int i3 = 0;

            // TODO: crc
            // if (m4281d().m4226a().contains(SensorFeatures.E2E_CRC)) {
            i = GattPayload.getNextLength(18);
            GattPayload gattPayload = payload;
            int i4 = extractedCount;
            // ChecksumVerifier.do_e2e_crc(gattPayload, i4, unpackInt - i, (unpackInt + i4)
            // - i);

            // TODO: replace constants from format types
            int len = extractedCount + GattPayload.getNextLength(17);
            extractedCount = len;
            int unpackInt2 = payload.unpackInt(PayloadFormat.FORMAT_UINT8, len);
            extractedCount += GattPayload.getNextLength(PayloadFormat.FORMAT_UINT8.getValue());
            Set<CgmMeasurementFlags> flags = IntEnumConverter.fromInt(unpackInt2, CgmMeasurementFlags.values());
            float unpackFloat = payload.unpackFloat(PayloadFormat.FORMAT_SFLOAT, extractedCount);
            int extractLowerNibble2 = extractedCount + GattPayload.getNextLength(50);
            extractedCount = extractLowerNibble2;
            int unpackInt3 = payload.unpackInt(PayloadFormat.FORMAT_UINT16, extractLowerNibble2);
            extractedCount += GattPayload.getNextLength(PayloadFormat.FORMAT_UINT16.getValue());
            if (flags.contains(CgmMeasurementFlags.SENSOR_STATUS_STATUS_PRESENT)) {
                i2 = payload.unpackInt(PayloadFormat.FORMAT_UINT8, extractedCount) | 0;
                extractedCount += GattPayload.getNextLength(17);
            } else {
                i2 = 0;
            }
            if (flags.contains(CgmMeasurementFlags.SENSOR_STATUS_CAL_TEMP_PRESENT)) {
                i3 = 0 | payload.unpackInt(PayloadFormat.FORMAT_UINT8, extractedCount); // TODO: two status flags are
                                                                                        // not working in the app?
                extractedCount += GattPayload.getNextLength(17);
            }
            int i5 = i3;
            if (flags.contains(CgmMeasurementFlags.SENSOR_STATUS_WARNING_PRESENT)) {
                i2 |= payload.unpackInt(PayloadFormat.FORMAT_UINT8, extractedCount) << 16;
                extractedCount += GattPayload.getNextLength(17);
            }
            int i6 = i2;
            if (flags.contains(CgmMeasurementFlags.CGM_TREND_INFO_PRESENT)) {
                Float valueOf = Float.valueOf(payload.unpackFloat(PayloadFormat.FORMAT_SFLOAT, extractedCount));
                extractedCount += GattPayload.getNextLength(50);
                f = valueOf;
            } else {
                f = null;
            }
            if (flags.contains(CgmMeasurementFlags.CGM_QUALITY_PRESENT)) {
                Float valueOf2 = Float.valueOf(payload.unpackFloat(PayloadFormat.FORMAT_SFLOAT, extractedCount));
                extractedCount += GattPayload.getNextLength(50);
                f2 = valueOf2;
            } else {
                f2 = null;
            }

            extractedCount += i;
            measurements.add(new CgmMeasurement(unpackInt2, unpackFloat, unpackInt3, i6, i5, f, f2));

        }
        return new CgmMeasurementList(measurements);
    }

    // @Override // p123e.p416g.p471f.p472a.p502e.p503a.ConvertUtils,
    // p123e.p416g.p471f.p472a.p502e.p503a.IDataConverter
    /* renamed from: l */
    /*
     * public CgmMeasurementList unpack(GattPayload gattPayload) {
     * var length = gattPayload.getCopy().length;
     * var helper = new PayloadListHelper(gattPayload);
     * while (old_helper_offset < payload.getCopy().length) {
     * //try {
     * m4234k(helper);
     * // } catch (UnpackException e) {
     * // super.printError(e, this.getClass());
     * //}
     * }
     * return new CgmMeasurementList(helper.cgmMeasurements);
     * }
     * 
     */

    @Override
    public byte[] pack(AbstractGattMessage message) throws PackException {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'pack'");
    }
}
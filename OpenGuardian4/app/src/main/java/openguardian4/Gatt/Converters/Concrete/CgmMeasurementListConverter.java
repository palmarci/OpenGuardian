package openguardian4.Gatt.Converters.Concrete;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import openguardian4.Gatt.Converters.AbstractMessageConverter;
import openguardian4.Gatt.Converters.UnpackException;
import openguardian4.Gatt.Enum.IntEnumConverter;
import openguardian4.Gatt.Message.GattPayload;
import openguardian4.Gatt.Message.Concrete.CgmMeasurement;
import openguardian4.Gatt.Message.Concrete.CgmMeasurementList;
import openguardian4.Gatt.Enum.Concrete.CgmMeasurementFlags;

public class CgmMeasurementListConverter extends AbstractMessageConverter {

    public static class PayloadListHelper {
        public final List<CgmMeasurement> cgmMeasurements = new ArrayList<CgmMeasurement>();
        public int offset = 0; //?
        public final GattPayload payload;

        public PayloadListHelper(GattPayload gattPayload) {
            this.payload = gattPayload;
        }
    }

    /* renamed from: k */
    public final void m4234k(PayloadListHelper helper) throws UnpackException {
        int i;
        int i2;
        Float f;
        Float f2;
        int unpackInt = helper.payload.unpackInt(17, helper.offset);
        int i3 = 0;
     //   if (m4281d().m4226a().contains(SensorFeatures.E2E_CRC)) {
        if (true) { //TODO crc
            i = helper.payload.extractLowerNibble(18);
            GattPayload gattPayload = helper.payload;
            int i4 = helper.offset;
           // ChecksumVerifier.do_e2e_crc(gattPayload, i4, unpackInt - i, (unpackInt + i4) - i);
        } else {
            i = 0;
        }

        //TODO replace constants from format types
        int extractLowerNibble = helper.offset + helper.payload.extractLowerNibble(17);
        helper.offset = extractLowerNibble;
        int unpackInt2 = helper.payload.unpackInt(17, extractLowerNibble);
        helper.offset += helper.payload.extractLowerNibble(17);
        Set<CgmMeasurementFlags> flags = IntEnumConverter.fromInt(unpackInt2, CgmMeasurementFlags.values());
        float unpackFloat = helper.payload.unpackFloat(50, helper.offset);
        int extractLowerNibble2 = helper.offset + helper.payload.extractLowerNibble(50);
        helper.offset = extractLowerNibble2;
        int unpackInt3 = helper.payload.unpackInt(18, extractLowerNibble2);
        helper.offset += helper.payload.extractLowerNibble(18);
        if (flags.contains(CgmMeasurementFlags.SENSOR_STATUS_STATUS_PRESENT)) {
            i2 = helper.payload.unpackInt(17, helper.offset) | 0;
            helper.offset += helper.payload.extractLowerNibble(17);
        } else {
            i2 = 0;
        }
        if (flags.contains(CgmMeasurementFlags.SENSOR_STATUS_CAL_TEMP_PRESENT)) {
            i3 = 0 | helper.payload.unpackInt(17, helper.offset); //TODO two status flags are not working in the app?
            helper.offset += helper.payload.extractLowerNibble(17);
        }
        int i5 = i3;
        if (flags.contains(CgmMeasurementFlags.SENSOR_STATUS_WARNING_PRESENT)) {
            i2 |= helper.payload.unpackInt(17, helper.offset) << 16;
            helper.offset += helper.payload.extractLowerNibble(17);
        }
        int i6 = i2;
        if (flags.contains(CgmMeasurementFlags.CGM_TREND_INFO_PRESENT)) {
            Float valueOf = Float.valueOf(helper.payload.unpackFloat(50, helper.offset));
            helper.offset += helper.payload.extractLowerNibble(50);
            f = valueOf;
        } else {
            f = null;
        }
        if (flags.contains(CgmMeasurementFlags.CGM_QUALITY_PRESENT)) {
            Float valueOf2 = Float.valueOf(helper.payload.unpackFloat(50, helper.offset));
            helper.offset += helper.payload.extractLowerNibble(50);
            f2 = valueOf2;
        } else {
            f2 = null;
        }
        helper.offset += i;
        helper.cgmMeasurements.add(new CgmMeasurement(unpackInt2, unpackFloat, unpackInt3, i6, i5, f, f2));
    }

    @Override // p123e.p416g.p471f.p472a.p502e.p503a.ConvertUtils,
              // p123e.p416g.p471f.p472a.p502e.p503a.IDataConverter
    /* renamed from: l */
    public CgmMeasurementList unpack(GattPayload gattPayload) {
        var helper  = new PayloadListHelper(gattPayload);
        while (helper.offset < helper.payload.getCopy().length) {
            try {
                m4234k(helper);
            } catch (UnpackException e) {
                // TODO Auto-generated catch block
                super.printError(e, this.getClass());
            }
        }
        return new CgmMeasurementList(helper.cgmMeasurements);
    }
}
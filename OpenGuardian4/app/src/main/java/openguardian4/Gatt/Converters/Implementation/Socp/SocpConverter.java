package openguardian4.Gatt.Converters.Implementation.Socp;

import java.util.Set;

import openguardian4.Gatt.Converters.IMessageConverter;
import openguardian4.Gatt.Converters.PackException;
import openguardian4.Gatt.Converters.UnpackException;
import openguardian4.Gatt.Enum.IntEnumConverter;
import openguardian4.Gatt.Enum.Implementation.SensorDetailFlags;
//import openguardian4.Gatt.Enum.Implementation.SensorFeatures;
import openguardian4.Gatt.Enum.Implementation.SocpOpcode;
import openguardian4.Gatt.Message.AbstractGattMessage;
import openguardian4.Gatt.Message.GattPayload;
import openguardian4.Gatt.Message.PayloadFormat;
import openguardian4.Gatt.Message.Implementation.Socp.Socp;
import openguardian4.Gatt.Message.Implementation.Socp.CalibrationDataRecord;
import openguardian4.Gatt.Message.Implementation.Socp.SensorDetails;
import openguardian4.Gatt.Message.Implementation.Socp.SocpOperand;

public class SocpConverter implements IMessageConverter {

    private int[] getSocpOpcodeInternalMap() {
        int[] iArr = new int[SocpOpcode.values().length];
        var copy = iArr;
        try {
            iArr[SocpOpcode.CONFIGURE_SENSOR.ordinal()] = 1;
        } catch (NoSuchFieldError unused) {
        }
        try {
            copy[SocpOpcode.GET_GLUCOSE_CALIBRATION_VALUE.ordinal()] = 2;
        } catch (NoSuchFieldError unused2) {
        }
        try {
            copy[SocpOpcode.READ_SESSION_START_TIME.ordinal()] = 3;
        } catch (NoSuchFieldError unused3) {
        }
        try {
            copy[SocpOpcode.SET_GLUCOSE_CALIBRATION_VALUE.ordinal()] = 4;
        } catch (NoSuchFieldError unused4) {
        }
        try {
            copy[SocpOpcode.GET_CALIBRATION_DETAILS.ordinal()] = 5;
        } catch (NoSuchFieldError unused5) {
        }
        try {
            copy[SocpOpcode.GET_SENSOR_DETAILS.ordinal()] = 6;
        } catch (NoSuchFieldError unused6) {
        }
        try {
            copy[SocpOpcode.READ_CURRENT_SESSION_ID.ordinal()] = 7;
        } catch (NoSuchFieldError unused7) {
        }
        try {
            copy[SocpOpcode.READ_TRANSMITTER_RTC.ordinal()] = 8;
        } catch (NoSuchFieldError unused8) {
        }
        try {
            copy[SocpOpcode.GET_CGM_OPERATING_LIMITS.ordinal()] = 9;
        } catch (NoSuchFieldError unused9) {
        }
        try {
            copy[SocpOpcode.SET_CALIBRATION_TRANSFER_DATA.ordinal()] = 10;
        } catch (NoSuchFieldError unused10) {
        }
        try {
            copy[SocpOpcode.SENSOR_INTEGRITY_REQUEST.ordinal()] = 11;
        } catch (NoSuchFieldError unused11) {
        }
        try {
            copy[SocpOpcode.CALIBRATION_VALUE_RESPONSE.ordinal()] = 12;
        } catch (NoSuchFieldError unused12) {
        }
        try {
            copy[SocpOpcode.READ_SESSION_START_TIME_RESPONSE.ordinal()] = 13;
        } catch (NoSuchFieldError unused13) {
        }
        try {
            copy[SocpOpcode.READ_CURRENT_SESSION_ID_RESPONSE.ordinal()] = 14;
        } catch (NoSuchFieldError unused14) {
        }
        try {
            copy[SocpOpcode.READ_TRANSMITTER_RTC_RESPONSE.ordinal()] = 15;
        } catch (NoSuchFieldError unused15) {
        }
        try {
            copy[SocpOpcode.GET_CALIBRATION_TRANSFER_DATA_RESPONSE.ordinal()] = 16;
        } catch (NoSuchFieldError unused16) {
        }
        try {
            copy[SocpOpcode.SENSOR_INTEGRITY_RESPONSE.ordinal()] = 17;
        } catch (NoSuchFieldError unused17) {
        }
        try {
            copy[SocpOpcode.GET_CGM_OPERATING_LIMITS_RESPONSE.ordinal()] = 18;
        } catch (NoSuchFieldError unused18) {
        }
        try {
            copy[SocpOpcode.CALIBRATION_DETAILS_RESPONSE.ordinal()] = 19;
        } catch (NoSuchFieldError unused19) {
        }
        try {
            copy[SocpOpcode.SENSOR_DETAILS_RESPONSE.ordinal()] = 20;
        } catch (NoSuchFieldError unused20) {
        }
        try {
            copy[SocpOpcode.RESPONSE.ordinal()] = 21;
        } catch (NoSuchFieldError unused21) {
        }
        return copy;

    }

    private SensorDetails unpackSensorDetails(GattPayload gattPayload, int i2) throws UnpackException {
        int i3;
        int i4;
        String str;
        int unpackInt = gattPayload.unpackInt(PayloadFormat.FORMAT_UINT8, i2);
        int nextLength = GattPayload.getNextLength(PayloadFormat.FORMAT_UINT8.getValue()) + i2;
        Set fromInt = IntEnumConverter.fromInt(unpackInt, SensorDetailFlags.values());
        int i5 = -1;
        if (fromInt.contains(SensorDetailFlags.SENSOR_DETAILS_ANNUNCIATION_PRESENT)) {
            i3 = gattPayload.unpackInt(PayloadFormat.FORMAT_CRC_SOMETHING, nextLength);
            nextLength += GattPayload.getNextLength(PayloadFormat.FORMAT_CRC_SOMETHING.getValue());
        } else {
            i3 = -1;
        }
        if (fromInt.contains(SensorDetailFlags.MAXIMUM_CALIBRATION_INTERVAL_PRESENT)) {
            i4 = gattPayload.unpackInt(PayloadFormat.FORMAT_CRC_SOMETHING, nextLength);
            nextLength += GattPayload.getNextLength(PayloadFormat.FORMAT_CRC_SOMETHING.getValue());
        } else {
            i4 = -1;
        }
        if (fromInt.contains(SensorDetailFlags.MAXIMUM_SENSOR_LIFE_PRESENT)) {
            i5 = gattPayload.unpackInt(PayloadFormat.FORMAT_CRC_SOMETHING, nextLength);
            nextLength += GattPayload.getNextLength(PayloadFormat.FORMAT_CRC_SOMETHING.getValue());
        }
        int i6 = i5;
        if (fromInt.contains(SensorDetailFlags.SENSOR_FLEX_VERSION_PRESENT)) {
            str = "CRC???";
            // str = ChecksumVerifier.getAsString(gattPayload.unpackInt(
            // PayloadFormat.FORMAT_CRC_SOMETHING, nextLength), 2);
            nextLength += GattPayload.getNextLength(PayloadFormat.FORMAT_CRC_SOMETHING.getValue());
        } else {
            str = "";
        }
        return new /* ShitWrapper<>(new */ SensorDetails(unpackInt, i3, i4, i6, str);// , nextLength - i2);
    }

    private CalibrationDataRecord unpackCalDataRecord(GattPayload gattPayload, int i2) throws UnpackException {
        float c5451f = gattPayload.unpackFloat(PayloadFormat.FORMAT_SFLOAT, i2);
        int nextLength = GattPayload.getNextLength(PayloadFormat.FORMAT_SFLOAT.getValue()) + i2;
        int unpackInt = gattPayload.unpackInt(PayloadFormat.FORMAT_CRC_SOMETHING, nextLength);
        int nextLength2 = nextLength + GattPayload.getNextLength(PayloadFormat.FORMAT_CRC_SOMETHING.getValue());
        int unpackInt2 = gattPayload.unpackInt(PayloadFormat.FORMAT_UINT8, nextLength2);
        int nextLength3 = nextLength2 + GattPayload.getNextLength(PayloadFormat.FORMAT_UINT8.getValue());
        int unpackInt3 = gattPayload.unpackInt(PayloadFormat.FORMAT_CRC_SOMETHING, nextLength3);
        int nextLength4 = nextLength3 + GattPayload.getNextLength(PayloadFormat.FORMAT_CRC_SOMETHING.getValue());
        int unpackInt4 = gattPayload.unpackInt(PayloadFormat.FORMAT_CRC_SOMETHING, nextLength4);
        int nextLength5 = nextLength4 + GattPayload.getNextLength(PayloadFormat.FORMAT_CRC_SOMETHING.getValue());
        return new CalibrationDataRecord(c5451f,
                unpackInt,
                unpackInt2 & 15,
                (unpackInt2 >> 4) & 15,
                unpackInt3,
                unpackInt4,
                (int) gattPayload.unpackInt(PayloadFormat.FORMAT_UINT8, nextLength5));
        // (nextLength5 + GattPayload.getNextLength(17)) - i2);
    }

    public Socp unpack(GattPayload gattPayload) throws UnpackException {
        // b m24798m;
        SocpOperand socpOperand;
        int nextLength;
        int i2;
        int rawOpcode = gattPayload.unpackInt(PayloadFormat.FORMAT_UINT8, 0);
        int opcodeSize = GattPayload.getNextLength(17) + 0;
        SocpOpcode parsedOpcode = (SocpOpcode) IntEnumConverter.pickValues(rawOpcode, SocpOpcode.values());
        var internalOpcodeMap = getSocpOpcodeInternalMap();
        switch (internalOpcodeMap[parsedOpcode.ordinal()]) {
            case 12:
                var calData = unpackCalDataRecord(gattPayload, opcodeSize);
                socpOperand = new SocpOperand(calData);
                // nextLength = m24798m.size;
                i2 = opcodeSize + opcodeSize;
                // if (m24732d().m24787a().contains(SensorFeatures.E2E_CRC)) {
                // i2 += ChecksumVerifier.do_e2e_crc(gattPayload, 0, i2, i2);
                // }
                // ChecksumVerifier.checkLength(gattPayload, i2);
                return new Socp(parsedOpcode, socpOperand);
            case 20:
                var sensorDetails = unpackSensorDetails(gattPayload, opcodeSize);
                socpOperand = new SocpOperand(sensorDetails);
                // = m24798m.size;
                i2 = opcodeSize + opcodeSize;

                // ChecksumVerifier.checkLength(gattPayload, i2);
                return new Socp(parsedOpcode, socpOperand);
            /*
             * case 13:
             * m24798m = m24802q(gattPayload, opcodeSize);
             * socpOperand = new SocpOperand(m24798m.value);
             * nextLength = m24798m.size;
             * i2 = opcodeSize + nextLength;
             * 
             * //ChecksumVerifier.checkLength(gattPayload, i2);
             * return new Socp(parsedOpcode, socpOperand);
             * case 14:
             * socpOperand = new SocpOperand(Integer.valueOf(gattPayload.unpackInt( 17,
             * opcodeSize)));
             * nextLength = GattPayload.getNextLength(17);
             * i2 = opcodeSize + nextLength;
             * 
             * //ChecksumVerifier.checkLength(gattPayload, i2);
             * return new Socp(parsedOpcode, socpOperand);
             * case 15:
             * m24798m = m24804s(gattPayload, opcodeSize);
             * socpOperand = new SocpOperand(m24798m.value);
             * nextLength = m24798m.size;
             * i2 = opcodeSize + nextLength;
             * 
             * //ChecksumVerifier.checkLength(gattPayload, i2);
             * return new Socp(parsedOpcode, socpOperand);
             * case 16:
             * socpOperand = new SocpOperand(gattPayload.m25178k(opcodeSize, 14));
             * i2 = opcodeSize + 14;
             * 
             * //ChecksumVerifier.checkLength(gattPayload, i2);
             * return new Socp(parsedOpcode, socpOperand);
             * case 17:
             * m24798m = m24801p(gattPayload, opcodeSize);
             * socpOperand = new SocpOperand(m24798m.value);
             * nextLength = m24798m.size;
             * i2 = opcodeSize + nextLength;
             * 
             * //ChecksumVerifier.checkLength(gattPayload, i2);
             * return new Socp(parsedOpcode, socpOperand);
             * case 18:
             * m24798m = m24800o(gattPayload, opcodeSize);
             * socpOperand = new SocpOperand(m24798m.value);
             * nextLength = m24798m.size;
             * i2 = opcodeSize + nextLength;
             * 
             * //ChecksumVerifier.checkLength(gattPayload, i2);
             * return new Socp(parsedOpcode, socpOperand);
             * case 19:
             * m24798m = m24799n(gattPayload, opcodeSize);
             * socpOperand = new SocpOperand(m24798m.value);
             * nextLength = m24798m.size;
             * i2 = opcodeSize + nextLength;
             * 
             * //ChecksumVerifier.checkLength(gattPayload, i2);
             * return new Socp(parsedOpcode, socpOperand);
             * 
             * case 21:
             * m24798m = m24803r(gattPayload, opcodeSize);
             * socpOperand = new SocpOperand(m24798m.value);
             * nextLength = m24798m.size;
             * i2 = opcodeSize + nextLength;
             * 
             * //ChecksumVerifier.checkLength(gattPayload, i2);
             * return new Socp(parsedOpcode, socpOperand);
             */
            default:
                throw new UnpackException("OpCode is not supported: " + parsedOpcode);
        }
    }

    @Override
    public byte[] pack(AbstractGattMessage message) throws PackException {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'pack'");
    }
}

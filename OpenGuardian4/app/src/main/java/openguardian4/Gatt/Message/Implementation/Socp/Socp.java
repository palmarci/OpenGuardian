package openguardian4.Gatt.Message.Implementation.Socp;

import java.util.Objects;

import openguardian4.Gatt.Enum.Implementation.SocpOpcode;
import openguardian4.Gatt.Message.AbstractGattMessage;


public class Socp extends AbstractGattMessage {

    private final SocpOpcode opCode;
    @SuppressWarnings("rawtypes")
    private final SocpOperand operand;

    public Socp(SocpOpcode socpOpcode, @SuppressWarnings("rawtypes") SocpOperand socpOperand) {
        this.opCode = socpOpcode;
        this.operand = socpOperand;
    }

    /* renamed from: a */
    @SuppressWarnings({ "rawtypes", "unchecked" })
    public static Socp getConfigureSensor(boolean z) {
        return new Socp(SocpOpcode.CONFIGURE_SENSOR, new SocpOperand(Integer.valueOf(z ? 1 : 0)));
    }

    /* renamed from: b */
    @SuppressWarnings({ "rawtypes", "unchecked" })
    public static Socp getCalibrationValue(int i2) {
        return new Socp(SocpOpcode.GET_GLUCOSE_CALIBRATION_VALUE, new SocpOperand(Integer.valueOf(i2)));
    }

    /* renamed from: c */
    @SuppressWarnings({ "rawtypes", "unchecked" })
    public static Socp getSensorDetails() {
        return new Socp(SocpOpcode.GET_SENSOR_DETAILS, new SocpOperand(null));
    }

    /* renamed from: d */
    @SuppressWarnings({ "rawtypes", "unchecked" })
    public static Socp getCurrentSessionId() {
        return new Socp(SocpOpcode.READ_CURRENT_SESSION_ID, new SocpOperand(null));
    }

    /* renamed from: e */
    @SuppressWarnings({ "rawtypes", "unchecked" })
    public static Socp readTransmitterRtc() {
        return new Socp(SocpOpcode.READ_TRANSMITTER_RTC, new SocpOperand(null));
    }

    /* renamed from: f */
    @SuppressWarnings({ "rawtypes", "unchecked" })
    public static Socp setGlucoseCalValue(CalibrationDataRecord socpCalibrationDataRecord) {
        return new Socp(SocpOpcode.SET_GLUCOSE_CALIBRATION_VALUE, new SocpOperand(socpCalibrationDataRecord));
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        Socp socp = (Socp) obj;
        return this.opCode == socp.opCode && Objects.equals(this.operand, socp.operand);
    }

    /* renamed from: g */
    public SocpOpcode getOpcode() {
        return this.opCode;
    }

    /* renamed from: h */
    @SuppressWarnings("rawtypes")
    public SocpOperand getOperand() {
        return this.operand;
    }

    public int hashCode() {
        return Objects.hash(this.opCode.getValue(), this.operand);
    }

    public String toString() {
        return "Socp{opCode=" + this.opCode + ", operand=" + this.operand + '}';
    }
}
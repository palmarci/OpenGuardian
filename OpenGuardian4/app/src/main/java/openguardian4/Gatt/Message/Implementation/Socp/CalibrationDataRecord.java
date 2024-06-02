package openguardian4.Gatt.Message.Implementation.Socp;

import java.util.Objects;

public class CalibrationDataRecord  {
    public static final CalibrationDataRecord EMPTY = new CalibrationDataRecord(0.0f, -1, -1, -1, -1, -1, -1);
    private final int calibrationRecordNumber;
    private final int calibrationSampleLocation;
    private final int calibrationStatus;
    private final int calibrationTime;
    private final int calibrationType;
    // private final C5451f glucoseConcentration;
    private final float glucoseConcentration;
    private final int nextCalibrationTime;

    public CalibrationDataRecord(float glucoseConcentration, int calibrationTime, int calibrationType, int i4,
            int i5, int i6, int i7) {
        this.glucoseConcentration = glucoseConcentration;
        this.calibrationTime = calibrationTime;
        this.calibrationType = calibrationType;
        this.calibrationSampleLocation = i4;
        this.nextCalibrationTime = i5;
        this.calibrationRecordNumber = i6;
        this.calibrationStatus = i7;
    }

    /* renamed from: a */
    public int m24588a() {
        return this.calibrationRecordNumber;
    }

    /* renamed from: b */
    public int getCalibrationStatus() {
        return this.calibrationStatus;
    }

    /* renamed from: c */
    public int getCalibrationTime() {
        return this.calibrationTime;
    }

    /* renamed from: d */
    public float getGlucoseConcentration() {
        return this.glucoseConcentration;
    }

    /* renamed from: e */
    public int getNextCalibTime() {
        return this.nextCalibrationTime;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && getClass() == obj.getClass()) {
            CalibrationDataRecord socpCalibrationDataRecord = (CalibrationDataRecord) obj;
            if (this.calibrationTime == socpCalibrationDataRecord.calibrationTime
                    && this.calibrationType == socpCalibrationDataRecord.calibrationType
                    && this.calibrationSampleLocation == socpCalibrationDataRecord.calibrationSampleLocation
                    && this.nextCalibrationTime == socpCalibrationDataRecord.nextCalibrationTime
                    && this.calibrationRecordNumber == socpCalibrationDataRecord.calibrationRecordNumber
                    && this.calibrationStatus == socpCalibrationDataRecord.calibrationStatus
                    && Objects.equals(this.glucoseConcentration, socpCalibrationDataRecord.glucoseConcentration)) {
                return true;
            }
        }
        return false;
    }

    public int hashCode() {
        return Objects.hash(this.glucoseConcentration, Integer.valueOf(this.calibrationTime),
                Integer.valueOf(this.calibrationType), Integer.valueOf(this.calibrationSampleLocation),
                Integer.valueOf(this.nextCalibrationTime), Integer.valueOf(this.calibrationRecordNumber),
                Integer.valueOf(this.calibrationStatus));
    }

    public String toString() {
        return "SocpCalibrationDataRecord{glucoseConcentration=" + this.glucoseConcentration + ", calibrationTime="
                + this.calibrationTime + ", calibrationType=" + this.calibrationType + ", calibrationSampleLocation="
                + this.calibrationSampleLocation + ", nextCalibrationTime=" + this.nextCalibrationTime
                + ", calibrationRecordNumber=" + this.calibrationRecordNumber + ", calibrationStatus="
                + this.calibrationStatus + '}';
    }
}
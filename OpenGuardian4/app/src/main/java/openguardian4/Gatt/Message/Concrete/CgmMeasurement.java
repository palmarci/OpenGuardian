package openguardian4.Gatt.Message.Concrete;

import java.util.Objects;
import java.util.Set;

import openguardian4.Gatt.Enum.IntEnumConverter;

import openguardian4.Gatt.Enum.Concrete.CgmSensorStatus;
import openguardian4.Gatt.Enum.Concrete.CgmCalibrationFlags;
import openguardian4.Gatt.Enum.Concrete.CgmMeasurementFlags;


/* renamed from: e.g.f.a.d.d.a.n.w.d */
/* loaded from: classes.dex */
public class CgmMeasurement {
    public static final CgmMeasurement EMPTY = new CgmMeasurement(0, 0, 0.0f, 0, 0, 0, null, null);
    private final float cgmGlucose;
    private final Float cgmQuality;
    private final Float cgmTrendInfo;
    private final int flags;
    private final long id;
    private final int sensorStatus;
    public final int sensorStatusCalTemp;
    private final int timeOffset;

    /* renamed from: e.g.f.a.d.d.a.n.w.d$a */
    /* loaded from: classes.dex */


    public CgmMeasurement(int i, float glucose, int i2, int i3, int i4, Float f2, Float f3) {
        this(0L, i, glucose, i2, i3, i4, f2, f3);
    }

    public CgmMeasurement(long j, int i, float f, int i2, int i3, int calTemp, Float f2, Float f3) {
        this.flags = i;
        this.id = j;
        this.cgmGlucose = f;
        this.timeOffset = i2;
        this.sensorStatus = i3;
        this.sensorStatusCalTemp = calTemp;
        this.cgmTrendInfo = f2;
        this.cgmQuality = f3;
    }

    /* renamed from: a */
    public float getGlucose() {
        return this.cgmGlucose;
    }

    /* renamed from: b */
    public Float getTrend() {
        return this.cgmTrendInfo;
    }

    public Set<CgmMeasurementFlags> getMeasurementFlags() {
        return IntEnumConverter.fromInt(this.flags, CgmMeasurementFlags.values());
    }

    /* renamed from: c */
    public Set<CgmSensorStatus> getSensorStatusFlags() {
        return IntEnumConverter.fromInt(this.sensorStatus, CgmSensorStatus.values());
    }

    /* renamed from: d */
    public Set<CgmCalibrationFlags> getCalibrationTempratureFlags() {
        return IntEnumConverter.fromInt(this.sensorStatusCalTemp, CgmCalibrationFlags.values());
    }

    /* renamed from: e */
    public int getTimeOffset() {
        return this.timeOffset;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        CgmMeasurement cgmMeasurement = (CgmMeasurement) obj;
        return this.id == cgmMeasurement.id && this.flags == cgmMeasurement.flags && Float.compare(cgmMeasurement.cgmGlucose, this.cgmGlucose) == 0 && this.timeOffset == cgmMeasurement.timeOffset && this.sensorStatus == cgmMeasurement.sensorStatus && this.sensorStatusCalTemp == cgmMeasurement.sensorStatusCalTemp && Objects.equals(this.cgmTrendInfo, cgmMeasurement.cgmTrendInfo) && Objects.equals(this.cgmQuality, cgmMeasurement.cgmQuality);
    }

    public int hashCode() {
        return Objects.hash(Long.valueOf(this.id), Integer.valueOf(this.flags), Float.valueOf(this.cgmGlucose), Integer.valueOf(this.timeOffset), Integer.valueOf(this.sensorStatus), Integer.valueOf(this.sensorStatusCalTemp), this.cgmTrendInfo, this.cgmQuality);
    }

    public String toString() {
        return "CgmMeasurement{id=" + this.id + ", flags=" + this.getMeasurementFlags() + ", cgmGlucose=" + this.cgmGlucose + ", timeOffset=" + this.timeOffset + ", sensorStatus=" + this.getSensorStatusFlags() + ", sensorStatusCalTemp=" + this.getCalibrationTempratureFlags() + ", cgmTrendInfo=" + this.cgmTrendInfo + ", cgmQuality=" + this.cgmQuality + '}';
    }
}
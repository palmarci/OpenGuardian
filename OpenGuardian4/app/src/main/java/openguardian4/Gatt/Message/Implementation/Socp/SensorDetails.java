package openguardian4.Gatt.Message.Implementation.Socp;

import java.util.Objects;
import java.util.Set;

//import openguardian4.Gatt.Enum.IGattEnum;
import openguardian4.Gatt.Enum.IntEnumConverter;
import openguardian4.Gatt.Enum.Implementation.SensorDetailAnnunciations;
import openguardian4.Gatt.Enum.Implementation.SensorDetailFlags;

public class SensorDetails {
    public static final SensorDetails EMPTY = new SensorDetails(-1, -1, -1, -1, "");
    private final int flags;
    private final int maximumCalibrationInterval;
    private final int maximumSensorLife;
    private final int sensorDetailAnnunciations;
    private final String sensorFlexPackageVersion;

    /* renamed from: e.g.f.a.d.d.a.n.w.a0.b$a */
    /* loaded from: classes.dex */

    public SensorDetails(int i2, int i3, int i4, int i5, String str) {
        this.flags = i2;
        this.sensorDetailAnnunciations = i3;
        this.maximumCalibrationInterval = i4;
        this.maximumSensorLife = i5;
        this.sensorFlexPackageVersion = str;
    }

    /* renamed from: a */
    public int getMaxSensorLife() {
        return this.maximumSensorLife;
    }

    /* renamed from: b */
    public Set<SensorDetailAnnunciations> getSensorDetailAnnunciations() {
        return IntEnumConverter.fromInt(this.sensorDetailAnnunciations, SensorDetailAnnunciations.values());
    }

    public Set<SensorDetailFlags> getSensorDetailFlags() {
        return IntEnumConverter.fromInt(this.flags, SensorDetailFlags.values());
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        SensorDetails sensorDetails = (SensorDetails) obj;
        return this.flags == sensorDetails.flags
                && this.sensorDetailAnnunciations == sensorDetails.sensorDetailAnnunciations
                && this.maximumCalibrationInterval == sensorDetails.maximumCalibrationInterval
                && this.maximumSensorLife == sensorDetails.maximumSensorLife
                && this.sensorFlexPackageVersion.equals(sensorDetails.sensorFlexPackageVersion);
    }

    public int hashCode() {
        return Objects.hash(Integer.valueOf(this.flags), Integer.valueOf(this.sensorDetailAnnunciations),
                Integer.valueOf(this.maximumCalibrationInterval), Integer.valueOf(this.maximumSensorLife),
                this.sensorFlexPackageVersion);
    }

    public String toString() {
        return "SensorDetails{flags=" + this.getSensorDetailFlags() + ", sensorDetailsAnnunciations=" + this.getSensorDetailAnnunciations()
                + ", maximumCalibrationInterval=" + this.maximumCalibrationInterval + ", maximumSensorLife="
                + this.maximumSensorLife + ", sensorFlexPackageVersion='" + this.sensorFlexPackageVersion + "'}";
    }
}
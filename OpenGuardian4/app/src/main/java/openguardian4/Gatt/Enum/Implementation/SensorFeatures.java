package openguardian4.Gatt.Enum.Implementation;

import openguardian4.Gatt.Enum.IGattEnum;

//public class SensorFeatureFlags {
    
public enum SensorFeatures implements IGattEnum<Integer> {
    CALIBRATION(1),
    PATIENT_HIGH_LOW_ALERTS(2),
    HYPO_ALERTS(4),
    HYPER_ALERTS(8),
    RATE_INCREASE_DECREASE_ALERTS(16),
    DEVICE_SPECIFIC_ALERT(32),
    SENSOR_MALFUNCTION_DETECTION(64),
    SENSOR_TEMPERATURE_HIGH_LOW_DETECTION(128),
    SENSOR_RESULT_HIGH_LOW_DETECTION(256),
    LOW_BATTERY_DETECTION(512),
    SENSOR_TYPE_ERROR_DETECTION(1024),
    GENERAL_DEVICE_FAULT(2048),
    E2E_CRC(4096),
    MULTIPLE_BOND(8192),
    MULTIPLE_SESSIONS(16384),
    CGM_TREND_INFORMATION(32768),
    CGM_QUALITY(65536);

    private final int value;

    SensorFeatures(int i2) {
        this.value = i2;
    }

    /* JADX WARN: Can't rename method to resolve collision */
    @Override // p121e.p414g.p469f.p470a.p512i.p514d.IGattEnum
    public Integer getValue() {
        return Integer.valueOf(this.value);
    }
}

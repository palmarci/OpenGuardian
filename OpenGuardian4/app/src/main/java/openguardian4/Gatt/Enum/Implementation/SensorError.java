package openguardian4.Gatt.Enum.Implementation;

import openguardian4.Gatt.Enum.IGattEnum;

public enum SensorError implements IGattEnum<Integer> {
    IS_ISIG_AN_ARTIFACT(1),
    IS_ISIG_INVALID(2),
    IS_SG_GENERATION_SIGNALS_OUT_OF_RANGE(4),
    IS_ISIG_NOISY(8),
    IS_SG_AN_OUTLIER(16),
    IS_HIGH_RATE_OF_CHANGE(32),
    IS_CALIBRATION_ERROR(64),
    IS_CALIBRATION_EXPIRATION(128),
    IS_SG_OUT_OF_RANGE(256),
    IS_IN_WARM_UP_PERIOD(512),
    OTHER(32768);
    
    private final int value;

    SensorError(int i) {
        this.value = i;
    }

    /* renamed from: getValue */
    public Integer getValue() {
        return Integer.valueOf(this.value);
    }
}
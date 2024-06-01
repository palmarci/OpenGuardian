package openguardian4.Gatt.Enum.Implementation;

import openguardian4.Gatt.Enum.IGattEnum;

public enum ChangeSensorError implements IGattEnum<Integer> {
    IS_NOISE_TERMINATION(1),
    IS_EIS_REAL1K_TERMINATION(2),
    IS_PERSISTENT_BLANKING_TERMINATION(4),
    IS_MAX_CALIBRATION_ERRORS_EXCEEDED(8),
    IS_QUADRATIC_DISCRIMINATION_TERMINATION(16),
    IS_HIGH_CF_VARIANCE(32),
    IS_SENSOR_EOL(64),
    OTHER(32768);
    
    private final int value;

    ChangeSensorError(int i) {
        this.value = i;
    }

    /* JADX WARN: Can't rename method to resolve collision */
    @Override // p123e.p416g.p471f.p472a.p514i.p516d.IGattEnumConverter
    /* renamed from: getValue */
    public Integer getValue() {
        return Integer.valueOf(this.value);
    }
}
package openguardian4.Gatt.Enum.Concrete;

import openguardian4.Gatt.Enum.IGattEnum;

public enum CgmCalibrationFlags implements IGattEnum<Integer> {
    TIME_SYNC_REQUIRED(1),
    CALIBRATION_NOT_ALLOWED(2),
    CALIBRATION_RECOMMENDED(4),
    CALIBRATION_REQUIRED(8),
    TEMPERATURE_HIGH(16),
    TEMPERATURE_LOW(32);
    
    private final int value;

    CgmCalibrationFlags(int i) {
        this.value = i;
    }

    /* JADX WARN: Can't rename method to resolve collision */
    @Override // p123e.p416g.p471f.p472a.p514i.p516d.IGattEnum
    public Integer getValue() {
        return Integer.valueOf(this.value);
    }
}
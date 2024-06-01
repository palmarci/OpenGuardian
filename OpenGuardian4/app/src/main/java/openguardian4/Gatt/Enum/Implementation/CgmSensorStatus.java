package openguardian4.Gatt.Enum.Implementation;

import openguardian4.Gatt.Enum.IGattEnum;

public enum CgmSensorStatus implements IGattEnum<Integer> {
    SENSOR_STATUS_ANNUNCIATION(1),
    DEVICE_BATTERY_LOW(2),
    SENSOR_TYPE_INCORRECT(4),
    SENSOR_MALFUNCTION(8),
    DEVICE_SPECIFIC_ALERT(16),
    GENERAL_SENSOR_FAULT(32);
    
    private final int value;

    CgmSensorStatus(int i) {
        this.value = i;
    }

    /* JADX WARN: Can't rename method to resolve collision */
    @Override // p123e.p416g.p471f.p472a.p514i.p516d.IGattEnum
    public Integer getValue() {
        return Integer.valueOf(this.value);
    }
}
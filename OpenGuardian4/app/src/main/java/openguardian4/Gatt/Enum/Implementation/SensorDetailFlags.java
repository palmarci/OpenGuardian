package openguardian4.Gatt.Enum.Implementation;

import openguardian4.Gatt.Enum.IGattEnum;

public enum SensorDetailFlags implements IGattEnum<Integer> {
    SENSOR_DETAILS_ANNUNCIATION_PRESENT(1),
    MAXIMUM_CALIBRATION_INTERVAL_PRESENT(2),
    MAXIMUM_SENSOR_LIFE_PRESENT(4),
    SENSOR_FLEX_VERSION_PRESENT(8);

    private final int value;

    SensorDetailFlags(int i2) {
        this.value = i2;
    }

    /* JADX WARN: Can't rename method to resolve collision */
    @Override // p121e.p414g.p469f.p470a.p512i.p514d.IGattEnum
    public Integer getValue() {
        return Integer.valueOf(this.value);
    }
}
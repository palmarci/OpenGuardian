package openguardian4.Gatt.Enum.Implementation;

import openguardian4.Gatt.Enum.IGattEnum;

public enum SensorDetailAnnunciations implements IGattEnum<Integer> {
    APPROVED_FOR_TREATMENT(1),
    DISPOSABLE_SENSOR(2),
    CALIBRATION_FREE(4),
    HAS_CALIBRATION_RECOMMENDED(8),
    HAS_WATER_INGRESS_DETECTION(16),
    CALIBRATION_TRANSFER_SUPPORTED(32);

    private final int value;

    SensorDetailAnnunciations(int i2) {
        this.value = i2;
    }

    /* JADX WARN: Can't rename method to resolve collision */
    @Override // p121e.p414g.p469f.p470a.p512i.p514d.IGattEnum
    public Integer getValue() {
        return Integer.valueOf(this.value);
    }
}
package openguardian4.Gatt.Enum.Concrete;

import openguardian4.Gatt.Enum.IGattEnum;

public enum AlgorithmDataFlags implements IGattEnum<Integer> {
    SENSOR_ERROR_REASON_PRESENT(1),
    CHANGE_SENSOR_ERROR_REASON_PRESENT(2);

    private final int value;

    AlgorithmDataFlags(int i) {
        this.value = i;
    }

    /* JADX WARN: Can't rename method to resolve collision */
    // @Override // p123e.p416g.p471f.p472a.p514i.p516d.InterfaceC7783c
    public Integer getValue() {
        return Integer.valueOf(this.value);
    }
}
package openguardian4.Gatt.Enum.Concrete;

import openguardian4.Gatt.Enum.IGattEnum;

public enum CgmMeasurementFlags implements IGattEnum<Integer> {
        CGM_TREND_INFO_PRESENT(1),
        CGM_QUALITY_PRESENT(2),
        SENSOR_STATUS_WARNING_PRESENT(32),
        SENSOR_STATUS_CAL_TEMP_PRESENT(64),
        SENSOR_STATUS_STATUS_PRESENT(128);
        
        private final int value;

        CgmMeasurementFlags(int i) {
            this.value = i;
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // p123e.p416g.p471f.p472a.p514i.p516d.IGattEnumConverter
        public Integer getValue() {
            return Integer.valueOf(this.value);
        }
    }
package openguardian4.Gatt.Message.Implementation;

import java.util.Set;

import openguardian4.Gatt.Enum.IntEnumConverter;
import openguardian4.Gatt.Enum.Implementation.SensorFeatures;
import openguardian4.Gatt.Message.AbstractGattMessage;

public class CgmFeatures extends AbstractGattMessage {
    private final Set<SensorFeatures> features;
    private final int sampleLocation;
    private final int type;

    public CgmFeatures(int rawFeatures, int i3, int i4) {
        this.features = IntEnumConverter.fromInt(rawFeatures, SensorFeatures.values());
        //this.features = i2;
        this.type = i3;
        this.sampleLocation = i4;
    }

    /* renamed from: a */
    public Set<SensorFeatures> getFeatures() {
        //return IntEnumConverter.fromInt(this.features, SensorFeatures.values());
        return this.features;
    }

    public String toString() {
        return "CgmFeature{features=" + this.features + ", type=" + this.type + ", sampleLocation="
                + this.sampleLocation + '}';
    }
}

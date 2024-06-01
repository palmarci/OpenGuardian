package openguardian4.Gatt.Message.Implementation;

import java.util.ArrayList;
import java.util.List;


import openguardian4.Gatt.Message.AbstractGattMessage;

public class CgmMeasurementList extends AbstractGattMessage {
    private final List<CgmMeasurement> values;

    public CgmMeasurementList(List<CgmMeasurement> list) {
        this.values = new ArrayList<CgmMeasurement>(list);
    }

    /* renamed from: a */
    public List<CgmMeasurement> copy() {
        return new ArrayList<CgmMeasurement>(this.values);
    }

    public List<CgmMeasurement> getValues() {
        return this.values;
    }

    @Override
    public String toString() {
        return this.getClass().getSimpleName() + "{" +
            " values='" + getValues() + "'" +
            "}";
    }


}
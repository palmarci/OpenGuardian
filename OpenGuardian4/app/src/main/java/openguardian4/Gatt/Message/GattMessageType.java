package openguardian4.Gatt.Message;

import java.util.Arrays;
import java.util.List;

import openguardian4.Gatt.Converters.*;
import openguardian4.Gatt.Converters.Implementation.AlgorithmDataConverter;
import openguardian4.Gatt.Converters.Implementation.CgmMeasurementListConverter;
import openguardian4.Gatt.Converters.Implementation.ConnectionActiveParamsConverter;

public enum GattMessageType {
    ConnectionActiveParams(Arrays.asList("5f0b2420-be34-11e4-bc62-0002a5d5c51b"), new ConnectionActiveParamsConverter()),
    AlgorithmData(Arrays.asList("00000205-0000-1000-0000-009132591325"), new AlgorithmDataConverter()),
    CgmMeasurementList(Arrays.asList("00002aa7-0000-1000-8000-00805f9b34fb"), new CgmMeasurementListConverter());

    public final List<String> supportedUuids;
    public final IMessageConverter converter;

    private GattMessageType(List<String> supportedUuids, IMessageConverter converter) {
        this.supportedUuids = supportedUuids;
        this.converter = converter;
    }
}

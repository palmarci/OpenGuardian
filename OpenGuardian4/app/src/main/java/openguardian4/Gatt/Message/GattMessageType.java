package openguardian4.Gatt.Message;

import java.util.Arrays;
import java.util.List;

import openguardian4.Gatt.Converters.*;
import openguardian4.Gatt.Converters.Implementation.AlgorithmDataConverter;
import openguardian4.Gatt.Converters.Implementation.CgmFeaturesConverter;
import openguardian4.Gatt.Converters.Implementation.CgmMeasurementListConverter;
import openguardian4.Gatt.Converters.Implementation.ConnectionActiveParamsConverter;
import openguardian4.Gatt.Converters.Implementation.Socp.SocpConverter;
//import openguardian4.Gatt.Message.Implementation.CgmFeatures;
//import openguardian4.Gatt.Message.Implementation.Socp.Socp;

public enum GattMessageType {
    ConnectionActiveParams(Arrays.asList("5f0b2420-be34-11e4-bc62-0002a5d5c51b"), new ConnectionActiveParamsConverter()),
    AlgorithmData(Arrays.asList("00000205-0000-1000-0000-009132591325"), new AlgorithmDataConverter()),
    CgmMeasurementList(Arrays.asList("00002aa7-0000-1000-8000-00805f9b34fb"), new CgmMeasurementListConverter()),
    CgmFeatures(Arrays.asList("00002aa8-0000-1000-8000-00805f9b34fb"), new CgmFeaturesConverter()),
    Socp(Arrays.asList("00002aac-0000-1000-8000-00805f9b34fb"), new SocpConverter());

    public final List<String> supportedUuids;
    public final IMessageConverter converter;

    private GattMessageType(List<String> supportedUuids, IMessageConverter converter) {
        this.supportedUuids = supportedUuids;
        this.converter = converter;
    }
}

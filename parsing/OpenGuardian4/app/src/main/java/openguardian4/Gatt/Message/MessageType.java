package openguardian4.Gatt.Message;

import openguardian4.Gatt.Converters.*;

public enum MessageType {
    ConnectionActiveParams("5f0b2420-be34-11e4-bc62-0002a5d5c51b", new ConnectionActiveParamsConverter());
    

    public final String uuid;
    public final IMessageConverter converter;

    private MessageType(String uuid, IMessageConverter converter) {
        this.uuid = uuid;
        this.converter = converter;
    }
}

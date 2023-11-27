package openguardian.Gatt.Converters;

import openguardian.Gatt.GattPayload;
import openguardian.Gatt.Messages.BaseMessage;

public interface IMessageConverter {
    
    BaseMessage unpack(GattPayload gattPayload);

}

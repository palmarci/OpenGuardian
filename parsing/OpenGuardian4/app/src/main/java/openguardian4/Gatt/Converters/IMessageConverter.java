package openguardian4.Gatt.Converters;

import openguardian4.Gatt.GattPayload;
import openguardian4.Gatt.Messages.BaseMessage;

public interface IMessageConverter {
    
    BaseMessage unpack(GattPayload gattPayload);

}

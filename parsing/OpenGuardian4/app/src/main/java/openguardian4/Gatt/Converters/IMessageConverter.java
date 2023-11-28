package openguardian4.Gatt.Converters;

import openguardian4.Gatt.GattPayload;
import openguardian4.Gatt.Message.BaseGattMessage;

public interface IMessageConverter {
    
    BaseGattMessage unpack(GattPayload gattPayload);

}

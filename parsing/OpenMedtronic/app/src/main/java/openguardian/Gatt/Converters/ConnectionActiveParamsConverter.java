package openguardian.Gatt.Converters;

import openguardian.Gatt.ConverterUtils;
import openguardian.Gatt.GattPayload;
import openguardian.Gatt.Messages.BaseMessage;
import openguardian.Gatt.Messages.ConnectionActiveParams;

public class ConnectionActiveParamsConverter implements IMessageConverter {

    @Override
    public BaseMessage unpack(GattPayload gattPayload) {
        // ConverterUtils.unpack
        // throw new UnsupportedOperationException("Unimplemented method 'unpack'");
        try {
           int unpackInt = ConverterUtils.unpackInt(gattPayload, 17, 0);
            int And15 = GattPayload.And15(17) + 0;
            int unpackInt2 = ConverterUtils.unpackInt(gattPayload, 18, And15);
            int And152 = And15 + GattPayload.And15(18);
            int unpackInt3 = ConverterUtils.unpackInt(gattPayload, 18, And152);
            int And153 = And152 + GattPayload.And15(18);
            int unpackInt4 = ConverterUtils.unpackInt(gattPayload, 18, And153);
                    // ChecksumVerifier.checkLength(gattPayload, And153 + GattPayload.And15(18)); //TODO
             return new ConnectionActiveParams(unpackInt, unpackInt2, unpackInt3, unpackInt4);
        } catch (Exception e) {
            // TODO Auto-generated catch block
            System.out.println("Could not parse payload:" + gattPayload.toString());
            e.printStackTrace();
            return null;
        }

    }

}

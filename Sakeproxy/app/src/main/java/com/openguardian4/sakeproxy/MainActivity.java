package com.openguardian4.sakeproxy;

import androidx.appcompat.app.AppCompatActivity;

import java.io.IOException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Toast;

//import com.openguardian4.sakeproxy.SakeHttp;
import com.openguardian4.sakeproxy.*;
import com.medtronic.SakeClient.SakeClient;

public class MainActivity extends AppCompatActivity {

    private SakeHttp sakeHttp;
    private int port = 8080;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        System.loadLibrary("android-sake-lib");
        //this.startServer();
        this.debugSake();
    }

    
    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (sakeHttp != null) {
            sakeHttp.stop();
        }
    }
    
    
  /*  public void onClickBtn(View v) {
        Toast.makeText(this, "Hello world! Im just a placeholder", Toast.LENGTH_LONG).show();
    }
    
*/

    private void startServer() {
        try {
            sakeHttp = new SakeHttp(port);
            sakeHttp.start();

            String logtext = "http server started on port " + Integer.toString((port));
          //  Toast.makeText(this, logtext, Toast.LENGTH_LONG).show();
            Utils.logPrint(logtext);

        } catch (IOException e) {
            Utils.logPrint(Utils.convertExceptionToString(e));
        }
    }

    
    private void debugSake() {

        // this key is working with md5sum 268e90d30eb751de9c1d98bdbd012414 ./Guardian_134/lib/armeabi-v7a/libandroid-sake-lib.so
        byte[] validKeyDb = Utils.hexStrToBytes(
                "5fe5928308010230f0b50df613f2e429c8c5e8713854add1a69b837235a3e974304d8055ccb397838b90823c73236d6a83dcc9db3a2a939ff16145ca4169ef93a7fa39b20962b05e57413bff8b3d61fce0dfef2c43b326");

          byte[] modifiedkey = Utils.hexStrToBytes(
                "5fe5728308010230f0b50df613f2e429c8c5e8713854add1a69b837235a3e974304d8055ccb397838b90823c73236d6a83dcc9db3a2a939ff16145ca4169ef93a7fa39b20962b05e57413bff8b3d61fce0dfef2c43b326");

            //TODO: older lib supports one less device, so it has to be changed however then the crc check needs to be patched/fixed
            //TODO: create sake server java bindings too

        try {
            SakeClient sakeClient = new SakeClient();
            boolean open = sakeClient.initKeyDb(modifiedkey);
            if (!open) {
                throw new Exception("Can not open key db!");
            }
            
            sakeClient.doHandshake(null);
            byte[] h1 = sakeClient.doHandshake(Utils.hexStrToBytes("02019d8ac19e2ba905fcb1082a1cf8602241026b"));
            String h1res = Utils.bytesToHexStr(h1);
            Utils.logPrint("Handshake step 1 result= " + h1res);
            Utils.logPrint("Current status = " + sakeClient.getLastError());

            

        } catch (Exception e) {
            Utils.logPrint(Utils.convertExceptionToString(e));
        }

    }
    

}
package com.openguardian4.sakeproxy;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Toast;

import com.medtronic.sake.SakeClient;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }


    private void startSake() {

        byte[] validKeyDb = Utils.hexStrToBytes("5fe5928308010230f0b50df613f2e429c8c5e8713854add1a69b837235a3e974304d8055ccb397838b90823c73236d6a83dcc9db3a2a939ff16145ca4169ef93a7fa39b20962b05e57413bff8b3d61fce0dfef2c43b326");

        try {
            SakeClient sakeClient = new SakeClient(validKeyDb);
            sakeClient.doHandshake(null);
            byte[] h1 = sakeClient.doHandshake(Utils.hexStrToBytes("02019d8ac19e2ba905fcb1082a1cf8602241026b"));
            String h1res = Utils.bytesToHexStr(h1);
            Utils.logPrint("Handshake step 1 result= " + h1res);

        } catch (Exception e) {
       //     Log.d("Main", e.toString());
            Utils.logPrint(e.toString());
        }

    }
    public void onClickBtn(View v)
    {
        Toast.makeText(this, "Started!", Toast.LENGTH_LONG).show();
        this.startSake();
    }
}
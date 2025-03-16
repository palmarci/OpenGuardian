package com.openguardian4.sakeproxy;

import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

import androidx.appcompat.app.AppCompatActivity; // Import the necessary AppCompatActivity
import com.medtronic.SakeServerWrapper;

public class MainActivity extends AppCompatActivity {

	private Button stepButton;
	private TextView statusLabel;
	private TextView logTextView;

	private SakeServerWrapper sakeServer = null;

	private int stepCount = 0;
	private String[] stepData = {
			null,
			"0000000000000000000000000000000000000000",
			"c41feeac76ba58d90838ff8264e0fbe118d82707",
			"6f2898a885704de55acd824c781795ebf3b8d841",
			"d9b6215cee5c834ee00f5b2e0eb92a264700a5b8"
	};
	private String keyDb = "f75995e70401011bc1bf7cbf36fa1e2367d795ff09211903da6afbe986b650f14179c0e6852e0ce393781078ffc6f51919e2eaefbde69b8eca21e41ab59b881a0bea0286ea91dc7582a86a714e1737f558f0d66dc1895c";

	private Handler handler = new Handler(Looper.getMainLooper()); // For UI updates on the main thread
	private int logTimeout = 500; // ms

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);

		this.statusLabel = findViewById(R.id.status_label);
		this.statusLabel.setText("Initializing...");
		System.setProperty("dalvik.vm.execution-mode", "int:transitive");

		this.logTextView = findViewById(R.id.logTextView); // Assuming you have a TextView for logs

		System.loadLibrary("android-sake-lib");
		this.initSake();
		this.statusLabel.setText("Ready!");

		this.stepButton = findViewById(R.id.step_button);
		this.stepButton.setOnClickListener(new View.OnClickListener() {
			@Override
			public void onClick(View v) {
				handshakeStep();
			}
		});

		// startLogcatPolling();
	}

	private void startLogcatPolling() {
		final Handler handler = new Handler(Looper.getMainLooper());
		final StringBuilder previousLog = new StringBuilder(); // To keep track of the previous logcat output

		new Thread(new Runnable() {
			@Override
			public void run() {
				while (true) {
					try {
						// Execute logcat command
						Process process = Runtime.getRuntime().exec("logcat -d");
						BufferedReader bufferedReader = new BufferedReader(
								new InputStreamReader(process.getInputStream()));

						StringBuilder log = new StringBuilder();
						String line;

						// Read the logcat output
						while ((line = bufferedReader.readLine()) != null) {
							log.append(line).append("\n");
						}

						// Update the TextView on the main thread
						handler.post(new Runnable() {
							@Override
							public void run() {

								logTextView.setText(log);
								// logTextView.scrollTo(0, logTextView.getHeight());

							}
						});

						Thread.sleep(logTimeout);
					} catch (IOException | InterruptedException e) {
						e.printStackTrace(); // Handle exception
					}
				}
			}
		}).start();
	}

	@Override
	protected void onDestroy() {
		super.onDestroy();
	}

	private void initSake() {
		Utils.logPrint(" **** init sake **** ");
		if (this.sakeServer != null) {
			this.sakeServer.Destroy();
		}
		byte[] keydb = Utils.hexStrToBytes(this.keyDb);
		this.sakeServer = new SakeServerWrapper();
		boolean isOpen = this.sakeServer.initKeyDb(keydb);
	}

	private void handshakeStep() {
		try {
			if (this.stepCount >= this.stepData.length) {
				this.initSake();
				this.stepCount = 0;
			}
			this.statusLabel.setText("Current step = " + stepCount);

			byte[] data = Utils.hexStrToBytes(this.stepData[this.stepCount]);
			byte[] resp = this.sakeServer.doHandshake(data);
			
			Utils.logPrint(
					"step " + this.stepCount + " (" + Utils.bytesToHexStr(data) + ") -> " + Utils.bytesToHexStr(resp));
			this.stepCount++;
			Utils.logPrint("\tlast err = " + this.sakeServer.getLastError());
		} catch (Exception e) {
			Utils.logPrint(Utils.exceptionToString(e));
		}
	}
}

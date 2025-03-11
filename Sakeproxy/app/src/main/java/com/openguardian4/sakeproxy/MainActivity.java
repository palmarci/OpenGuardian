package com.openguardian4.sakeproxy;

import android.os.Bundle;
import android.os.Looper;
import android.os.Handler;
import android.util.Log;

import android.view.View;
import android.widget.Button;
import android.widget.ScrollView;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;

import com.medtronic.SakeClient.SakeClient;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class MainActivity extends AppCompatActivity {

	private static final int PORT = 8080; // Declare constants in upper case
	private SakeHttp sakeHttp;
	private TextView logTextView;
	private Button middleButton;
	private ScrollView logScrollView;
	private SakeClient sakeClient;

	private Handler handler = new Handler(Looper.getMainLooper()); // Handler to run on the main thread
	private Runnable logUpdateRunnable;
	private static final long LOG_UPDATE_INTERVAL = 500; // Update logs every 5 seconds (5000 ms)


	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);

		// Load the necessary native library
		System.loadLibrary("android-sake-lib");

		// Initialize views
		initializeViews();

			  // Set up periodic log fetching
		setupLogUpdater();

		// Set up the middle button onClickListener
		middleButton.setOnClickListener(v -> debugSake());
	}

	// Initialize the UI elements
	private void initializeViews() {
		logTextView = findViewById(R.id.log_text_view);
		middleButton = findViewById(R.id.middle_button);
		logScrollView = findViewById(R.id.log_scroll_view);
	}

	@Override
	protected void onDestroy() {
		super.onDestroy();
		if (sakeHttp != null) {
			sakeHttp.stop();
		}
	}

	// Start the HTTP server
	private void startServer() {
		try {
			sakeHttp = new SakeHttp(PORT);
			sakeHttp.start();

			String logtext = "HTTP server started on port " + PORT;
			Utils.logPrint(logtext);

		} catch (IOException e) {
			Utils.logPrint(Utils.convertExceptionToString(e));
		}
	}

	public void debugSake() {
		byte[] keydb = Utils.hexStrToBytes("f75995e70401011bc1bf7cbf36fa1e2367d795ff09211903da6afbe986b650f14179c0e6852e0ce393781078ffc6f51919e2eaefbde69b8eca21e41ab59b881a0bea0286ea91dc7582a86a714e1737f558f0d66dc1895c");

		try {
			this.sakeClient = new SakeClient();
			boolean isOpen = this.sakeClient.initKeyDb(keydb);
			if (!isOpen) {
				throw new Exception("Cannot open key db!");
			}

			this.sakeClient.doHandshake(null);


			byte[] h1 = this.sakeClient.doHandshake(Utils.hexStrToBytes("02019d8ac19e2ba905fcb1082a1cf8602241026b"));
			String h1res = Utils.bytesToHexStr(h1);
			Utils.logPrint("Handshake step 1 result= " + h1res);
			Utils.logPrint("Current status = " + this.sakeClient.getLastError());

		} catch (Exception e) {
			Utils.logPrint(Utils.convertExceptionToString(e));
		}
	}


	 @Override
	protected void onResume() {
		super.onResume();
		// Start the periodic log fetching when the activity is visible
		handler.post(logUpdateRunnable);
	}

	@Override
	protected void onPause() {
		super.onPause();
		// Stop the periodic log fetching when the activity is no longer visible
		handler.removeCallbacks(logUpdateRunnable);
	}

	// This method sets up a periodic log fetching runnable
	private void setupLogUpdater() {
		logUpdateRunnable = new Runnable() {
			@Override
			public void run() {
				fetchAndDisplayLogs();  // Fetch and display logs
				handler.postDelayed(this, LOG_UPDATE_INTERVAL); // Repeat after the specified interval
			}
		};
	}

	// This method fetches logs and updates the TextView
	private void fetchAndDisplayLogs() {
		new Thread(new Runnable() {
			@Override
			public void run() {
				try {
					// Execute the logcat command to fetch logs
					Process process = Runtime.getRuntime().exec("logcat -d"); // "-d" is for dumping the logs
					BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(process.getInputStream()));
					
					StringBuilder log = new StringBuilder();
					String line;
					
					// Read the logs line by line
					while ((line = bufferedReader.readLine()) != null) {
						log.append(line).append("\n");
					}
					
					// Update the TextView on the main thread with the fetched logs
					final String logData = log.toString();
					runOnUiThread(new Runnable() {
						@Override
						public void run() {
							logTextView.setText(logData); // Set the logs to the TextView

							// Optionally, scroll to the bottom of the log TextView
							logScrollView.post(new Runnable() {
								@Override
								public void run() {
									logScrollView.fullScroll(ScrollView.FOCUS_DOWN);
								}
							});
						}
					});

				} catch (IOException e) {
					// Handle any IO exceptions here
					runOnUiThread(new Runnable() {
						@Override
						public void run() {
							logTextView.setText("Error fetching logs: " + e.getMessage());
						}
					});
				}
			}
		}).start();
	}



}

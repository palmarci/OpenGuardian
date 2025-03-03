setTimeout(function () {
	Java.perform(function () {


        /*
		let CompatibilityStatusToConfigurationStatus = Java.use("a5.a");
		CompatibilityStatusToConfigurationStatus["apply"].implementation = function () {
			console.log(`CompatibilityStatusToConfigurationStatus.apply is called`);
			let result = this["apply"]();
			console.log(`CompatibilityStatusToConfigurationStatus.apply result=${result}`);
			return result;
		};
        */


        /*
        let BasePresenter = Java.use("com.medtronic.minimed.ui.base.BasePresenter");
        BasePresenter["onConfigurationStatusChanged"].implementation = function (configurationStatus) {
            console.log(`BasePresenter.onConfigurationStatusChanged is called: configurationStatus=${configurationStatus}`);
            this["onConfigurationStatusChanged"](configurationStatus);
        };*/

        let ConfigurationStatus = Java.use("com.medtronic.minimed.bl.configmonitor.DeviceConfigurationMonitor$ConfigurationStatus");
        var supportedEnum = ConfigurationStatus["SUPPORTED"].value;



        let AppStartupMessagePresenter = Java.use("com.medtronic.minimed.ui.startupwizard.AppStartupMessagePresenter");
        AppStartupMessagePresenter["handleConfigurationStatus"].implementation = function (configurationStatus) {
            console.log(`AppStartupMessagePresenter.handleConfigurationStatus is called: configurationStatus=${configurationStatus}`);
            this["handleConfigurationStatus"](supportedEnum);       
        };

      //  let ConfigurationStatus = Java.use("com.medtronic.minimed.bl.configmonitor.DeviceConfigurationMonitor$ConfigurationStatus");
        ConfigurationStatus["isCommunicationAllowed"].implementation = function () {
            console.log(`ConfigurationStatus.isCommunicationAllowed is called`);
            let result = this["isCommunicationAllowed"]();
            console.log(`ConfigurationStatus.isCommunicationAllowed result=${result}`);
            return result;
        };


        let DeviceConfigurationMonitor = Java.use("com.medtronic.minimed.bl.configmonitor.DeviceConfigurationMonitor");
        DeviceConfigurationMonitor["a"].implementation = function () {
            console.log(`DeviceConfigurationMonitor.mo270a is called`);
            let result = this["a"]();
            console.log(`DeviceConfigurationMonitor.mo270a result=${result}`);
            return result;
        };


        let SecurityStatusToConfigurationStatus = Java.use("a5.i");
        SecurityStatusToConfigurationStatus["apply"].implementation = function (device_supported_typeVar) {
            console.log(`SecurityStatusToConfigurationStatus.apply is called=${device_supported_typeVar}`);
            let result = this["apply"](supportedEnum);
            console.log(`SecurityStatusToConfigurationStatus.apply result=${result}`);
            return result;
        };


        let DeviceConfigurationMonitorImpl = Java.use("a5.g");
        DeviceConfigurationMonitorImpl["k"].implementation = function (deviceConfigurationMonitorImpl, device_supported_typeVar) {
            console.log(`DeviceConfigurationMonitorImpl.m268k is called: deviceConfigurationMonitorImpl=${deviceConfigurationMonitorImpl}, device_supported_typeVar=${device_supported_typeVar}`);
            let result = this["k"](deviceConfigurationMonitorImpl, device_supported_typeVar);
            console.log(`DeviceConfigurationMonitorImpl.m268k result=${result}`);
            return result;
        };


	});
}, 0);


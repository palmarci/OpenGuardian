setTimeout(function () {

	Java.perform(function () {

		console.log("[i] started")

		var activity = Java.use("com.medtronic.minimed.data.carelink.model.MobileSecurityConfigurations");

		
		activity.$init.overload('boolean', 'boolean').implementation = function (arg0, arg1) {

			console.log("init called: ", arg0 + ", " + arg1);

			return this.init.overload('boolean', 'boolean').call(this, false, false);
		}
	});

}, 0);
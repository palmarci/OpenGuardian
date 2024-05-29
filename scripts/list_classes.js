Java.perform(function() {
    setTimeout(function() {
        Java.enumerateLoadedClasses({
            onMatch: function(className) {
                console.log(className);
            },
            onComplete: function() {}
        });
    }, 2000);
});
console.log("waiting for 2 secs for app init...");
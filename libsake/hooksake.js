// class created from
// struct JNINativeInterface :
// https://android.googlesource.com/platform/libnativehelper/+/master/include_jni/jni.h#129
const jni_struct_array = ["reserved0", "reserved1", "reserved2", "reserved3", "GetVersion", "DefineClass", "FindClass", "FromReflectedMethod", "FromReflectedField", "ToReflectedMethod", "GetSuperclass", "IsAssignableFrom", "ToReflectedField", "Throw", "ThrowNew", "ExceptionOccurred", "ExceptionDescribe", "ExceptionClear", "FatalError", "PushLocalFrame", "PopLocalFrame", "NewGlobalRef", "DeleteGlobalRef", "DeleteLocalRef", "IsSameObject", "NewLocalRef", "EnsureLocalCapacity", "AllocObject", "NewObject", "NewObjectV", "NewObjectA", "GetObjectClass", "IsInstanceOf", "GetMethodID", "CallObjectMethod", "CallObjectMethodV", "CallObjectMethodA", "CallBooleanMethod", "CallBooleanMethodV", "CallBooleanMethodA", "CallByteMethod", "CallByteMethodV", "CallByteMethodA", "CallCharMethod", "CallCharMethodV", "CallCharMethodA", "CallShortMethod", "CallShortMethodV", "CallShortMethodA", "CallIntMethod", "CallIntMethodV", "CallIntMethodA", "CallLongMethod", "CallLongMethodV", "CallLongMethodA", "CallFloatMethod", "CallFloatMethodV", "CallFloatMethodA", "CallDoubleMethod", "CallDoubleMethodV", "CallDoubleMethodA", "CallVoidMethod", "CallVoidMethodV", "CallVoidMethodA", "CallNonvirtualObjectMethod", "CallNonvirtualObjectMethodV", "CallNonvirtualObjectMethodA", "CallNonvirtualBooleanMethod", "CallNonvirtualBooleanMethodV", "CallNonvirtualBooleanMethodA", "CallNonvirtualByteMethod", "CallNonvirtualByteMethodV", "CallNonvirtualByteMethodA", "CallNonvirtualCharMethod", "CallNonvirtualCharMethodV", "CallNonvirtualCharMethodA", "CallNonvirtualShortMethod", "CallNonvirtualShortMethodV", "CallNonvirtualShortMethodA", "CallNonvirtualIntMethod", "CallNonvirtualIntMethodV", "CallNonvirtualIntMethodA", "CallNonvirtualLongMethod", "CallNonvirtualLongMethodV", "CallNonvirtualLongMethodA", "CallNonvirtualFloatMethod", "CallNonvirtualFloatMethodV", "CallNonvirtualFloatMethodA", "CallNonvirtualDoubleMethod", "CallNonvirtualDoubleMethodV", "CallNonvirtualDoubleMethodA", "CallNonvirtualVoidMethod", "CallNonvirtualVoidMethodV", "CallNonvirtualVoidMethodA", "GetFieldID", "GetObjectField", "GetBooleanField", "GetByteField", "GetCharField", "GetShortField", "GetIntField", "GetLongField", "GetFloatField", "GetDoubleField", "SetObjectField", "SetBooleanField", "SetByteField", "SetCharField", "SetShortField", "SetIntField", "SetLongField", "SetFloatField", "SetDoubleField", "GetStaticMethodID", "CallStaticObjectMethod", "CallStaticObjectMethodV", "CallStaticObjectMethodA", "CallStaticBooleanMethod", "CallStaticBooleanMethodV", "CallStaticBooleanMethodA", "CallStaticByteMethod", "CallStaticByteMethodV", "CallStaticByteMethodA", "CallStaticCharMethod", "CallStaticCharMethodV", "CallStaticCharMethodA", "CallStaticShortMethod", "CallStaticShortMethodV", "CallStaticShortMethodA", "CallStaticIntMethod", "CallStaticIntMethodV", "CallStaticIntMethodA", "CallStaticLongMethod", "CallStaticLongMethodV", "CallStaticLongMethodA", "CallStaticFloatMethod", "CallStaticFloatMethodV", "CallStaticFloatMethodA", "CallStaticDoubleMethod", "CallStaticDoubleMethodV", "CallStaticDoubleMethodA", "CallStaticVoidMethod", "CallStaticVoidMethodV", "CallStaticVoidMethodA", "GetStaticFieldID", "GetStaticObjectField", "GetStaticBooleanField", "GetStaticByteField", "GetStaticCharField", "GetStaticShortField", "GetStaticIntField", "GetStaticLongField", "GetStaticFloatField", "GetStaticDoubleField", "SetStaticObjectField", "SetStaticBooleanField", "SetStaticByteField", "SetStaticCharField", "SetStaticShortField", "SetStaticIntField", "SetStaticLongField", "SetStaticFloatField", "SetStaticDoubleField", "NewString", "GetStringLength", "GetStringChars", "ReleaseStringChars", "NewStringUTF", "GetStringUTFLength", "GetStringUTFChars", "ReleaseStringUTFChars", "GetArrayLength", "NewObjectArray", "GetObjectArrayElement", "SetObjectArrayElement", "NewBooleanArray", "NewByteArray", "NewCharArray", "NewShortArray", "NewIntArray", "NewLongArray", "NewFloatArray", "NewDoubleArray", "GetBooleanArrayElements", "GetByteArrayElements", "GetCharArrayElements", "GetShortArrayElements", "GetIntArrayElements", "GetLongArrayElements", "GetFloatArrayElements", "GetDoubleArrayElements", "ReleaseBooleanArrayElements", "ReleaseByteArrayElements", "ReleaseCharArrayElements", "ReleaseShortArrayElements", "ReleaseIntArrayElements", "ReleaseLongArrayElements", "ReleaseFloatArrayElements", "ReleaseDoubleArrayElements", "GetBooleanArrayRegion", "GetByteArrayRegion", "GetCharArrayRegion", "GetShortArrayRegion", "GetIntArrayRegion", "GetLongArrayRegion", "GetFloatArrayRegion", "GetDoubleArrayRegion", "SetBooleanArrayRegion", "SetByteArrayRegion", "SetCharArrayRegion", "SetShortArrayRegion", "SetIntArrayRegion", "SetLongArrayRegion", "SetFloatArrayRegion", "SetDoubleArrayRegion", "RegisterNatives", "UnregisterNatives", "MonitorEnter", "MonitorExit", "GetJavaVM", "GetStringRegion", "GetStringUTFRegion", "GetPrimitiveArrayCritical", "ReleasePrimitiveArrayCritical", "GetStringCritical", "ReleaseStringCritical", "NewWeakGlobalRef", "DeleteWeakGlobalRef", "ExceptionCheck", "NewDirectByteBuffer", "GetDirectBufferAddress", "GetDirectBufferCapacity", "GetObjectRefType"]

var library_name = "libandroid-sake-lib.so" // ex: libsqlite.so
var function_name = "Java_com_medtronic_minimed_sake_SakeJNI_Sake_1KeyDatabase_1Open" // ex: JNI_OnLoad
var library_loaded = 0

// Hook all function to have an overview of the function called
function hook_all(jnienv_addr) {
    jni_struct_array.forEach(function(func_name) {
        // Calculating the address of the function
        if (!func_name.includes("reserved")) {
            var func_addr = getJNIFunctionAdress(jnienv_addr, func_name)
            Interceptor.attach(func_addr, {
                onEnter: function(args) {
                    console.log("[+] Entered : " + func_name)
                }
            })
        }
    })
}
// Function that will process the JNICall after calculating it from
// the jnienv pointer in args[0]
function hook_jni(library_name, function_name) {
    // To get the list of exports
    Module.enumerateExportsSync(library_name).forEach(function(symbol) {
        //  if(symbol.name == function_name){
        console.log("[...] Hooking : " + library_name + " -> " + function_name + " at " + symbol.address)
        Interceptor.attach(symbol.address, {
            onEnter: function(args) {
                var jnienv_addr = 0x0
                Java.perform(function() {
                    jnienv_addr = Java.vm.getEnv().handle.readPointer();
                });
                console.log("[+] Hooked successfully, JNIEnv base adress :" + jnienv_addr)
                /*
                 Here you can choose which function to hook
                 Either you hook all to have an overview of the function called
                */
                hook_all(jnienv_addr)
            },
            onLeave: function(args) {
                // Prevent from displaying junk from other functions
                Interceptor.detachAll()
                console.log("[-] Detaching all interceptors")
            }
        })
        //     }
    })
}
if (library_name == "" || function_name == "") {
    console.log("[-] You must provide a function name and a library name to hook");
} else {
    // First Step : waiting for the application to load the good library
    // https://android.googlesource.com/platform/system/core/+/master/libnativeloader/native_loader.cpp#746
    // 
    // OpenNativeLibrary is called when you loadLibrary from Java, it then call android_dlopen_ext
    Interceptor.attach(Module.findExportByName(null, 'android_dlopen_ext'), {
        onEnter: function(args) {
            // first arg is the path to the library loaded
            var library_path = Memory.readCString(args[0])
            if (library_path.includes(library_name)) {
                console.log("[...] Loading library : " + library_path)
                library_loaded = 1
            }
        },
        onLeave: function(args) {
            // if it's the library we want to hook, hooking it
            if (library_loaded == 1) {
                console.log("[+] Loaded")
                hook_jni(library_name, function_name)
                library_loaded = 0
            }
        }
    })
}
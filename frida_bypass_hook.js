// OstadRESpy Universal Frida Hook & SSL Pinning Bypass Engine
// Author: Ostad Rezaul Karim | Director, Ostad Red Team Forge
// Target: base

Java.perform(function() {
    console.log("[*] OstadRESpy DBI Hook Attached!");

    // 1. Universal SSL Pinning Bypass (TrustManager)
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var TrustManager = Java.registerClass({
            name: 'com.ostadrespy.TrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; }
            }
        });
        var TrustManagers = [TrustManager.$new()];
        var SSLContext_init = SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
        SSLContext_init.implementation = function(km, tm, random) {
            console.log("[+] OstadRESpy: SSLContext.init() intercepted, replacing with TrustAllManager");
            SSLContext_init.call(this, km, TrustManagers, random);
        };
    } catch(e) {
        console.log("[-] SSL Pinning hook error: " + e);
    }

    // 2. Root Detection Bypass
    try {
        var File = Java.use('java.io.File');
        File.exists.implementation = function() {
            var path = this.getAbsolutePath();
            if (path.indexOf("su") !== -1 || path.indexOf("Superuser") !== -1 || path.indexOf("magisk") !== -1) {
                console.log("[+] OstadRESpy: Root file check blocked for: " + path);
                return false;
            }
            return this.exists.call(this);
        };
    } catch(e) {}
});

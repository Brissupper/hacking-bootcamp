Java.perform(function () {
    console.log("[*] Production Frida Hook: Obfuscated calc evasion...");

    Java.enumerateLoadedClasses({
        onMatch: function(name) {
            if (name.includes("bc.b") || name.includes("MainActivity")) console.log("[+] Loaded: " + name);
        },
        onComplete: function() { console.log("[+] Enum complete."); }
    });

    // Input hook: J() for button spoof
    try {
        var MainActivity = Java.use("com.simplemobiletools.calculator.activities.MainActivity");
        MainActivity.J.implementation = function(textView, str) {
            console.log("[+] J hooked: " + str);
            if (str === "2") str = "99";  // Evasion: Spoof input
            return this.J(textView, str);
        };
    } catch (e) { console.log("[-] J hook error: " + e); }

    // Calc hook: bc.b for result manipulation
    try {
        var CalcClass = Java.use("bc.b");
        // Enum methods (run once to find calc)
        var methods = CalcClass.class.getDeclaredMethods();
        for (var i = 0; i < methods.length; i++) {
            console.log("[+] bc.b method: " + methods[i].getName() + " - " + methods[i].getReturnType().getName());
        }
        // Hook calc method (assume 'a' returns String, takes String - replace with actual)
        CalcClass.a.implementation = function(expr) {
            console.log("[+] Calc hooked: " + expr);
            var result = this.a(expr);
            console.log("[+] Real: " + result);
            // Evasion: Add 100
            var fake = (parseFloat(result) + 100).toString();
            console.log("[!] Fake: " + fake);
            return fake;
        };
    } catch (e) { console.log("[-] bc.b hook error: " + e); }
});

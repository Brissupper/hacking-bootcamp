Java.perform(function () {
    console.log("[*] Frida Calc Hook Rewritten: Enumerating classes and manipulating...");

    // Step 1: Enumerate loaded classes for inspection
    Java.enumerateLoadedClasses({
        onMatch: function(name) {
            // Filter for relevant classes (optional: comment out to list all)
            if (name.includes("calculator") || name.includes("Button") || name.includes("View")) {
                console.log("[+] Loaded Class: " + name);
            }
        },
        onComplete: function() {
            console.log("[+] Class enumeration complete.");
        }
    });

    // Step 2: Hook Button.setOnClickListener to intercept and modify clicks
    try {
        var Button = Java.use("android.widget.Button");
        Button.setOnClickListener.implementation = function (listener) {
            console.log("Hook attached to button");
            console.log("[+] Hooked Button.setOnClickListener on: " + this.getText());

            // Create proxy listener for manipulation
            var originalListener = listener;
            var proxyListener = Java.registerClass({
                name: 'ProxyOnClickListener',
                implements: [Java.use('android.view.View$OnClickListener')],
                methods: {
                    onClick: function (view) {
                        console.log("[+] Button clicked: " + view.getClass().getName());
                        // Manipulation: If button text is "2", change to "3" and force display
                        if (view instanceof Button) {
                            var text = view.getText().toString();
                            if (text === "2") {
                                console.log("[!] Manipulating: Changing '2' to '3'");
                                view.setText("3");  // Modify text
                                // Optional: Simulate another click or action
                            }
                        }
                        // Call original listener
                        originalListener.onClick(view);
                    }
                }
            });

            // Set proxy as listener
            this.setOnClickListener(proxyListener.$new());
        };
        console.log("[+] Button hook set.");
    } catch (e) {
        console.log("[-] Button hook failed: " + e.message);
    }

    // Step 3: Attempt app-specific hook (will fail without decompile—Day 2 fix)
    try {
        // Placeholder: Replace with real class from decompile (e.g., MainActivity)
        var MainActivity = Java.use("com.simplemobiletools.calculator.activities.MainActivity");
        MainActivity.onCreate.implementation = function (savedInstanceState) {
            console.log("[+] Hooked MainActivity.onCreate - Injecting custom behavior");
            // Example: Log or modify app startup
            this.onCreate(savedInstanceState);
        };
        console.log("[+] App-specific hook set.");
    } catch (e) {
        console.log("[-] App-specific hook failed: " + e.message + " - Decompile APK for real classes");
    }
});

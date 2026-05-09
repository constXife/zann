import QtQuick 2.15
import QtTest 1.2

TestCase {
    name: "RemoteSetupFlow"
    property int waitMs: 2500

    function createApp() {
        var component = Qt.createComponent(Qt.resolvedUrl("../../qml/main.qml"));
        compare(component.status, Component.Ready, component.errorString());
        var root = component.createObject(null);
        verify(root !== null);
        root.visible = true;
        return root;
    }

    function findByName(root, name) {
        function walk(node) {
            if (!node) return null;
            if (node.objectName === name) return node;
            var kids = node.children;
            if (kids) {
                for (var i = 0; i < kids.length; i++) {
                    var hit = walk(kids[i]);
                    if (hit) return hit;
                }
            }
            var data = node.data;
            if (data) {
                for (var j = 0; j < data.length; j++) {
                    var hit2 = walk(data[j]);
                    if (hit2) return hit2;
                }
            }
            return null;
        }
        var obj = walk(root);
        verify(obj !== null, "Missing object: " + name);
        return obj;
    }

    function waitForAppState(appModel, state) {
        tryVerify(function() { return appModel.app_state === state; }, waitMs);
    }

    function waitForItemCount(root, count) {
        tryVerify(function() { return root.itemsData.length === count; }, waitMs);
    }

    function test_remote_connect_create_and_unlock() {
        var dbUrl = "sqlite:///tmp/zann-kde-ui-test-remote-" + Date.now() + ".sqlite";
        var root = createApp();
        var appModel = findByName(root, "appModel");

        appModel.debug_cleanup_db(dbUrl);
        appModel.debug_reset_core(dbUrl);
        waitForAppState(appModel, "welcome");

        appModel.start_connect();
        waitForAppState(appModel, "connect");

        appModel.debug_force_remote_setup("test-storage-id", false);
        waitForAppState(appModel, "password");

        var passwordInput = findByName(root, "setupPasswordInput");
        var confirmInput = findByName(root, "setupConfirmInput");
        var submitButton = findByName(root, "setupSubmitButton");

        passwordInput.text = "12312345";
        confirmInput.text = "12312345";
        mouseClick(submitButton, Qt.LeftButton);

        tryVerify(function() { return appModel.unlocked === true; }, waitMs);
        appModel.debug_create_kv_item("kv/remote", "alpha", "beta");
        waitForItemCount(root, 1);
        root.visible = false;
        root.destroy();
        wait(0);

        var root2 = createApp();
        var appModel2 = findByName(root2, "appModel");
        appModel2.debug_reset_core(dbUrl);
        waitForAppState(appModel2, "unlock");

        var unlockPassword = findByName(root2, "unlockPasswordInput");
        var unlockButton = findByName(root2, "unlockSubmitButton");
        unlockPassword.text = "12312345";
        mouseClick(unlockButton, Qt.LeftButton);

        tryVerify(function() { return appModel2.unlocked === true; }, waitMs);
        waitForItemCount(root2, 1);
        appModel2.debug_cleanup_db(dbUrl);
        root2.visible = false;
        root2.destroy();
        wait(0);
    }
}

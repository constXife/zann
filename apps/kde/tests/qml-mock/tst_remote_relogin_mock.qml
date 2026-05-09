import QtQuick 2.15
import QtTest 1.2

TestCase {
    name: "RemoteReloginMock"
    property int waitMs: 15000

    function createApp() {
        var component = Qt.createComponent(Qt.resolvedUrl("../../qml/main.qml"));
        compare(component.status, Component.Ready, component.errorString());
        var root = component.createObject(null);
        verify(root !== null);
        root.visible = true;
        return root;
    }

    function waitForAppState(appModel, state) {
        tryVerify(function() { return appModel.app_state === state; }, waitMs);
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

    function waitForConnectReady(appModel) {
        tryVerify(function() {
            return appModel.connect_methods.length > 0
                || appModel.connect_status === "password"
                || appModel.connect_error.length > 0;
        }, waitMs);
    }

    function setPersonalKeys(serverUrl, email, enabled) {
        var xhr = new XMLHttpRequest();
        xhr.open("POST", serverUrl + "/__test__/personal-keys", false);
        xhr.setRequestHeader("Content-Type", "application/json");
        xhr.send(JSON.stringify({ email: email, enabled: enabled }));
        compare(xhr.status, 200, xhr.responseText);
    }

    function test_remote_relogin_mock() {
        var root = createApp();
        var appModel = findByName(root, "appModel");
        if (appModel.debug_get_env("ZANN_E2E_MODE") !== "mock") {
            root.visible = false;
            root.destroy();
            skip("mock flow disabled");
        }

        var serverUrl = appModel.debug_get_env("ZANN_E2E_SERVER_URL");
        if (serverUrl.length === 0) {
            serverUrl = "http://127.0.0.1:18081";
        }
        var loginPassword = appModel.debug_get_env("ZANN_E2E_LOGIN_PASSWORD");
        if (loginPassword.length === 0) {
            loginPassword = "E2ePass123!";
        }
        var masterPassword = appModel.debug_get_env("ZANN_E2E_MASTER_PASSWORD");
        if (masterPassword.length === 0) {
            masterPassword = loginPassword;
        }
        var email = "e2e-" + Date.now() + "@example.com";

        var dbUrl = appModel.debug_make_temp_db_url("remote-mock");
        verify(dbUrl.length > 0, "failed to create temp db url");

        appModel.debug_cleanup_db(dbUrl);
        appModel.debug_reset_core(dbUrl);
        tryVerify(function() { return appModel.app_state !== "loading"; }, waitMs);
        waitForAppState(appModel, "welcome");

        appModel.start_connect();
        waitForAppState(appModel, "connect");

        appModel.connect_server_url = serverUrl;
        appModel.begin_server_connect();
        waitForConnectReady(appModel);
        verify(appModel.connect_error.length === 0, appModel.connect_error);

        appModel.connect_with_password(email, loginPassword, "E2E User", "register");
        waitForAppState(appModel, "password");
        appModel.create_master_password(masterPassword, masterPassword);
        tryVerify(function() { return appModel.unlocked === true; }, waitMs);

        setPersonalKeys(serverUrl, email, true);

        root.visible = false;
        root.destroy();
        wait(0);

        var root2 = createApp();
        var appModel2 = findByName(root2, "appModel");
        appModel2.debug_reset_core(dbUrl);
        waitForAppState(appModel2, "unlock");

        appModel2.start_connect();
        waitForAppState(appModel2, "connect");
        appModel2.connect_server_url = serverUrl;
        appModel2.begin_server_connect();
        waitForConnectReady(appModel2);
        verify(appModel2.connect_error.length === 0, appModel2.connect_error);

        appModel2.connect_with_password(email, loginPassword, "", "login");
        waitForAppState(appModel2, "password");
        appModel2.create_master_password(masterPassword, masterPassword);
        tryVerify(function() { return appModel2.unlocked === true; }, waitMs);

        appModel2.debug_cleanup_db(dbUrl);
        root2.visible = false;
        root2.destroy();
        wait(0);
    }
}

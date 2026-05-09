import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import org.kde.kirigami 2.20 as K

Item {
    id: serverConnect

    property string serverUrl: ""
    property string connectStatus: ""
    property string connectError: ""
    property bool connectBusy: false
    property string connectLoginId: ""
    property string connectVerification: ""
    property string connectOldFp: ""
    property string connectNewFp: ""
    property var connectMethods: []
    property string connectPasswordMode: "login"
    property bool showPasswordForm: false
    property string passwordMode: connectPasswordMode
    property bool passwordModeOverridden: false
    property bool inStepTwo: (serverConnect.connectMethods && serverConnect.connectMethods.length > 0)
        || serverConnect.connectStatus !== ""
        || serverConnect.showPasswordForm

    onConnectPasswordModeChanged: {
        if (!passwordModeOverridden) {
            passwordMode = connectPasswordMode;
        }
    }

    signal back()
    signal beginConnect()
    signal connectOidc()
    signal connectPassword(string email, string password, string fullName, string mode)
    signal trustFingerprint()
    signal pollOidc()
    signal serverUrlEdited(string value)

    onConnectMethodsChanged: {
        showPasswordForm = connectMethods
            && connectMethods.length === 1
            && connectMethods[0] === "password";
    }

    ColumnLayout {
        anchors.centerIn: parent
        width: Math.min(400, parent.width - K.Units.gridUnit * 4)
        spacing: 0

        StackLayout {
            id: connectSteps
            Layout.fillWidth: true
            currentIndex: serverConnect.inStepTwo ? 1 : 0

            // Step 1: server URL
            ColumnLayout {
                Layout.fillWidth: true
                spacing: K.Units.largeSpacing

                RowLayout {
                    Layout.fillWidth: true

                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 2

                        Label {
                            text: qsTr("Step 1 of 2")
                            font: K.Theme.smallFont
                            color: K.Theme.disabledTextColor
                        }

                        K.Heading {
                            text: qsTr("Connect to Server")
                            level: 2
                        }
                    }

                    Button {
                        text: qsTr("Back")
                        flat: true
                        enabled: !serverConnect.connectBusy
                        onClicked: serverConnect.back()
                    }
                }

                Label {
                    text: qsTr("Enter your organization's Zann server URL to sync your passwords across devices.")
                    wrapMode: Text.Wrap
                    Layout.fillWidth: true
                    color: K.Theme.disabledTextColor
                }

                TextField {
                    id: serverUrlInput
                    Layout.fillWidth: true
                    placeholderText: qsTr("https://zann.example.com")
                    enabled: !serverConnect.connectBusy
                    inputMethodHints: Qt.ImhUrlCharactersOnly
                    text: serverConnect.serverUrl
                    onTextEdited: serverConnect.serverUrlEdited(text)
                }

                Button {
                    Layout.fillWidth: true
                    Layout.preferredHeight: K.Units.gridUnit * 3
                    text: serverConnect.connectBusy ? qsTr("Checking...") : qsTr("Continue")
                    enabled: !serverConnect.connectBusy
                    icon.name: "network-connect"
                    onClicked: serverConnect.beginConnect()

                    BusyIndicator {
                        anchors.centerIn: parent
                        running: serverConnect.connectBusy
                        visible: serverConnect.connectBusy
                        width: K.Units.iconSizes.small
                        height: K.Units.iconSizes.small
                    }
                }
            }

            // Step 2: sign-in / verification
            ColumnLayout {
                Layout.fillWidth: true
                spacing: K.Units.largeSpacing

                RowLayout {
                    Layout.fillWidth: true

                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 2

                        Label {
                            text: qsTr("Step 2 of 2")
                            font: K.Theme.smallFont
                            color: K.Theme.disabledTextColor
                        }

                        K.Heading {
                            text: qsTr("Sign in")
                            level: 2
                        }
                    }

                    Button {
                        text: qsTr("Back")
                        flat: true
                        enabled: !serverConnect.connectBusy
                        onClicked: serverConnect.back()
                    }
                }

                // Method selection
                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: K.Units.smallSpacing
                    visible: serverConnect.connectMethods
                        && serverConnect.connectMethods.length > 1
                        && serverConnect.connectStatus === ""

                    Label {
                        text: qsTr("Choose a sign-in method")
                        color: K.Theme.disabledTextColor
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: K.Units.smallSpacing

                        Button {
                            visible: serverConnect.connectMethods.indexOf("oidc") !== -1
                            text: qsTr("Sign in with browser")
                            enabled: !serverConnect.connectBusy
                            onClicked: serverConnect.connectOidc()
                        }

                        Button {
                            visible: serverConnect.connectMethods.indexOf("password") !== -1
                            text: qsTr("Sign in with password")
                            enabled: !serverConnect.connectBusy
                            onClicked: serverConnect.showPasswordForm = true
                        }
                    }
                }

                // Password form
                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: K.Units.smallSpacing
                    visible: serverConnect.showPasswordForm
                        && (serverConnect.connectStatus === "" || serverConnect.connectStatus === "password")

                    TextField {
                        id: emailInput
                        Layout.fillWidth: true
                        placeholderText: qsTr("Email")
                        enabled: !serverConnect.connectBusy
                        inputMethodHints: Qt.ImhEmailCharactersOnly
                    }

                    TextField {
                        id: passwordInput
                        Layout.fillWidth: true
                        placeholderText: qsTr("Password")
                        echoMode: TextInput.Password
                        enabled: !serverConnect.connectBusy
                    }

                    TextField {
                        id: fullNameInput
                        Layout.fillWidth: true
                        placeholderText: qsTr("Full name (optional)")
                        visible: serverConnect.passwordMode === "register"
                        enabled: !serverConnect.connectBusy
                    }

                    Button {
                        Layout.fillWidth: true
                        Layout.preferredHeight: K.Units.gridUnit * 3
                        text: serverConnect.passwordMode === "register"
                            ? qsTr("Create account")
                            : qsTr("Sign in")
                        enabled: !serverConnect.connectBusy
                            && emailInput.text.length > 0
                            && passwordInput.text.length > 0
                        onClicked: serverConnect.connectPassword(
                            emailInput.text,
                            passwordInput.text,
                            fullNameInput.text,
                            serverConnect.passwordMode
                        )
                    }

                    Button {
                        Layout.alignment: Qt.AlignHCenter
                        flat: true
                        text: serverConnect.passwordMode === "register"
                            ? qsTr("Already have an account? Sign in")
                            : qsTr("No account yet? Create one")
                        enabled: !serverConnect.connectBusy
                        onClicked: {
                            serverConnect.passwordModeOverridden = true;
                            serverConnect.passwordMode = serverConnect.passwordMode === "register"
                                ? "login"
                                : "register";
                        }
                    }
                }

                // OIDC waiting state
                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: K.Units.smallSpacing
                    visible: serverConnect.connectStatus === "waiting"

                    Label {
                        text: qsTr("Approve this device in your browser to continue.")
                        wrapMode: Text.Wrap
                        color: K.Theme.disabledTextColor
                    }

                    Button {
                        Layout.fillWidth: true
                        text: qsTr("Open verification link")
                        enabled: serverConnect.connectVerification.length > 0
                        onClicked: Qt.openUrlExternally(serverConnect.connectVerification)
                    }

                    TextField {
                        Layout.fillWidth: true
                        readOnly: true
                        text: serverConnect.connectVerification
                    }

                    Label {
                        visible: serverConnect.connectLoginId.length > 0
                        text: qsTr("Login id: %1").arg(serverConnect.connectLoginId)
                        color: K.Theme.disabledTextColor
                    }
                }

                // Fingerprint trust flow
                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: K.Units.smallSpacing
                    visible: serverConnect.connectStatus === "fingerprint"

                    Label {
                        text: qsTr("Server fingerprint has changed.")
                        wrapMode: Text.Wrap
                        color: K.Theme.disabledTextColor
                    }

                    Label {
                        text: qsTr("Old: %1").arg(serverConnect.connectOldFp.length > 0 ? serverConnect.connectOldFp : qsTr("Unknown"))
                    }

                    Label {
                        text: qsTr("New: %1").arg(serverConnect.connectNewFp.length > 0 ? serverConnect.connectNewFp : qsTr("Unknown"))
                    }

                    Button {
                        Layout.fillWidth: true
                        text: qsTr("Trust fingerprint")
                        enabled: !serverConnect.connectBusy
                        onClicked: serverConnect.trustFingerprint()
                    }
                }

                // Success
                K.InlineMessage {
                    Layout.fillWidth: true
                    visible: serverConnect.connectStatus === "success"
                    type: K.MessageType.Positive
                    text: qsTr("Connected. Continue to set up your vault.")
                }

                // Error message
                K.InlineMessage {
                    Layout.fillWidth: true
                    visible: serverConnect.connectError.length > 0
                    type: K.MessageType.Error
                    text: serverConnect.connectError
                }
            }
        }
    }

    Timer {
        interval: 500
        running: serverConnect.connectStatus === "waiting"
        repeat: true
        onTriggered: serverConnect.pollOidc()
    }
}

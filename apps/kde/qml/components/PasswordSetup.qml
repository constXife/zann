import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import org.kde.kirigami 2.20 as K

Item {
    id: passwordSetup

    property string setupError: ""
    property bool setupBusy: false
    property string passwordMode: "create"

    signal createPassword(string password, string confirm)
    signal back()

    // Password strength calculation
    function calculateStrength(pwd) {
        if (!pwd || pwd.length < 8) return "weak";

        var score = 0;
        if (pwd.length >= 12) score++;
        if (pwd.length >= 16) score++;
        if (/[a-z]/.test(pwd)) score++;
        if (/[A-Z]/.test(pwd)) score++;
        if (/[0-9]/.test(pwd)) score++;
        if (/[^a-zA-Z0-9]/.test(pwd)) score++;

        if (score <= 2) return "weak";
        if (score <= 4) return "medium";
        return "strong";
    }

    ColumnLayout {
        anchors.centerIn: parent
        width: Math.min(400, parent.width - K.Units.gridUnit * 4)
        spacing: K.Units.largeSpacing

        // Header with back button
        RowLayout {
            Layout.fillWidth: true

            ColumnLayout {
                Layout.fillWidth: true
                spacing: 2

                Label {
                    text: qsTr("Step 1 of 1")
                    font: K.Theme.smallFont
                    color: K.Theme.disabledTextColor
                }

                K.Heading {
                    text: passwordSetup.passwordMode === "unlock"
                        ? qsTr("Unlock Vault")
                        : qsTr("Create Master Password")
                    level: 2
                }
            }

            Button {
                objectName: "setupBackButton"
                text: qsTr("Back")
                flat: true
                enabled: !passwordSetup.setupBusy
                onClicked: passwordSetup.back()
            }
        }

        Label {
            text: passwordSetup.passwordMode === "unlock"
                ? qsTr("Enter your master password to unlock your vault.")
                : qsTr("This password will be used to encrypt all your data. Make sure to remember it - it cannot be recovered.")
            wrapMode: Text.Wrap
            Layout.fillWidth: true
            color: K.Theme.disabledTextColor
        }

        // Password input
        TextField {
            id: passwordInput
            objectName: "setupPasswordInput"
            Layout.fillWidth: true
            echoMode: TextInput.Password
            placeholderText: qsTr("Master password")
            enabled: !passwordSetup.setupBusy
        }

        // Password strength indicator
        ColumnLayout {
            Layout.fillWidth: true
            spacing: K.Units.smallSpacing
            visible: passwordSetup.passwordMode !== "unlock" && passwordInput.text.length > 0

            RowLayout {
                Layout.fillWidth: true
                spacing: K.Units.smallSpacing

                Rectangle {
                    Layout.fillWidth: true
                    height: 4
                    radius: 2
                    color: K.Theme.disabledTextColor
                    opacity: 0.3

                    Rectangle {
                        height: parent.height
                        radius: 2
                        width: {
                            var strength = passwordSetup.calculateStrength(passwordInput.text);
                            if (strength === "weak") return parent.width * 0.33;
                            if (strength === "medium") return parent.width * 0.66;
                            return parent.width;
                        }
                        color: {
                            var strength = passwordSetup.calculateStrength(passwordInput.text);
                            if (strength === "weak") return K.Theme.negativeTextColor;
                            if (strength === "medium") return K.Theme.neutralTextColor;
                            return K.Theme.positiveTextColor;
                        }
                        Behavior on width { NumberAnimation { duration: 200 } }
                        Behavior on color { ColorAnimation { duration: 200 } }
                    }
                }

                Label {
                    text: {
                        var strength = passwordSetup.calculateStrength(passwordInput.text);
                        if (strength === "weak") return qsTr("Weak");
                        if (strength === "medium") return qsTr("Medium");
                        return qsTr("Strong");
                    }
                    font: K.Theme.smallFont
                    color: {
                        var strength = passwordSetup.calculateStrength(passwordInput.text);
                        if (strength === "weak") return K.Theme.negativeTextColor;
                        if (strength === "medium") return K.Theme.neutralTextColor;
                        return K.Theme.positiveTextColor;
                    }
                }
            }
        }

        // Confirm password input
        TextField {
            id: confirmInput
            objectName: "setupConfirmInput"
            Layout.fillWidth: true
            echoMode: TextInput.Password
            placeholderText: qsTr("Confirm password")
            enabled: !passwordSetup.setupBusy
            visible: passwordSetup.passwordMode !== "unlock"
        }

        // Error message
        K.InlineMessage {
            Layout.fillWidth: true
            visible: passwordSetup.setupError.length > 0
            type: K.MessageType.Error
            text: passwordSetup.setupError
        }

        // Create button
        Button {
            objectName: "setupSubmitButton"
            Layout.fillWidth: true
            Layout.preferredHeight: K.Units.gridUnit * 3
            text: passwordSetup.setupBusy
                ? (passwordSetup.passwordMode === "unlock" ? qsTr("Unlocking...") : qsTr("Creating..."))
                : (passwordSetup.passwordMode === "unlock" ? qsTr("Unlock Vault") : qsTr("Create Vault"))
            icon.name: passwordSetup.setupBusy ? "" : (passwordSetup.passwordMode === "unlock" ? "object-unlocked" : "document-new")
            enabled: !passwordSetup.setupBusy && (
                passwordSetup.passwordMode === "unlock"
                    ? passwordInput.text.length > 0
                    : passwordInput.text.length >= 8
            )
            onClicked: passwordSetup.createPassword(passwordInput.text, confirmInput.text)

            BusyIndicator {
                anchors.centerIn: parent
                running: passwordSetup.setupBusy
                visible: passwordSetup.setupBusy
                width: K.Units.iconSizes.small
                height: K.Units.iconSizes.small
            }
        }
    }
}

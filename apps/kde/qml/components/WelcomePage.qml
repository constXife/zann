import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import org.kde.kirigami 2.20 as K

Item {
    id: welcomePage

    signal startLocalSetup()
    signal startConnect()

    ColumnLayout {
        anchors.centerIn: parent
        width: Math.min(400, parent.width - K.Units.gridUnit * 4)
        spacing: K.Units.largeSpacing * 2

        K.Icon {
            source: "security-high"
            Layout.preferredWidth: K.Units.iconSizes.huge
            Layout.preferredHeight: K.Units.iconSizes.huge
            Layout.alignment: Qt.AlignHCenter
        }

        ColumnLayout {
            Layout.fillWidth: true
            spacing: K.Units.smallSpacing

            K.Heading {
                text: qsTr("Welcome to Zann")
                level: 1
                Layout.alignment: Qt.AlignHCenter
            }

            Label {
                text: qsTr("Secure password manager for your digital life")
                wrapMode: Text.Wrap
                Layout.fillWidth: true
                horizontalAlignment: Text.AlignHCenter
                color: K.Theme.disabledTextColor
            }
        }

        ColumnLayout {
            Layout.fillWidth: true
            spacing: K.Units.largeSpacing

            Button {
                Layout.fillWidth: true
                Layout.preferredHeight: K.Units.gridUnit * 3
                text: qsTr("Connect to Server")
                icon.name: "network-server"
                onClicked: welcomePage.startConnect()
            }

            Button {
                Layout.fillWidth: true
                Layout.preferredHeight: K.Units.gridUnit * 3
                text: qsTr("Use on This Device")
                icon.name: "drive-harddisk"
                flat: true
                onClicked: welcomePage.startLocalSetup()
            }

            Label {
                text: qsTr("You can connect to a server later")
                font: K.Theme.smallFont
                color: K.Theme.disabledTextColor
                Layout.alignment: Qt.AlignHCenter
            }
        }
    }
}

import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import org.kde.kirigami 2.20 as K
import org.kde.kirigami.delegates as KD
import org.zann 1.0
import "components"

K.ApplicationWindow {
  id: root
  width: 1100
  height: 720
  visible: true
  title: "Zann"
  property bool isNarrow: width < 980
  property string appState: appModel.app_state
  property var categoriesData: JSON.parse(appModel.categories_json || "[]")
  property var foldersData: JSON.parse(appModel.folders_json || "{\"items_without_folder\":0,\"tree\":[]}")
  property int filteredItemsCount: appModel.filtered_items_count
  property var selectedItemData: appModel.selected_item_json && appModel.selected_item_json.length > 0
    ? JSON.parse(appModel.selected_item_json)
    : null
  property bool loadingMore: false
  property var itemCache: ({})

  function itemAt(index) {
    if (itemCache[index] !== undefined) {
      return itemCache[index]
    }
    var raw = appModel.filtered_item_json(index);
    if (!raw || raw.length === 0) {
      itemCache[index] = null
      return null;
    }
    try {
      var obj = JSON.parse(raw);
      if (!obj || !obj.id) {
        itemCache[index] = null
        return null;
      }
      itemCache[index] = obj
      return obj;
    } catch (err) {
      itemCache[index] = null
      return null;
    }
  }

  Connections {
    target: appModel
    function onFiltered_items_countChanged() {
      root.loadingMore = false
      root.itemCache = ({})
    }
  }

  property var revealedFields: ({})
  property string copiedFieldKey: ""
  property var payloadFields: selectedItemData ? parsePayloadFields(selectedItemData.payload_json) : []

  function prettyPayload(payloadText) {
    if (!payloadText || payloadText.length === 0) {
      return "";
    }
    try {
      return JSON.stringify(JSON.parse(payloadText), null, 2);
    } catch (err) {
      return payloadText;
    }
  }

  function parsePayloadFields(payloadText) {
    if (!payloadText) return [];
    try {
      var payload = JSON.parse(payloadText);
      var fields = payload.fields || {};
      var result = [];
      for (var key in fields) {
        var field = fields[key];
        var meta = field.meta || {};
        result.push({
          key: key,
          label: formatFieldLabel(key),
          value: field.value || "",
          kind: field.kind || "text",
          masked: meta.masked !== undefined ? meta.masked : (field.kind === "password" || field.kind === "otp"),
          copyable: meta.copyable !== undefined ? meta.copyable : true
        });
      }
      return result;
    } catch (err) { return []; }
  }

  function formatFieldLabel(key) {
    var labels = {
      "username": qsTr("Username"),
      "password": qsTr("Password"),
      "url": qsTr("URL"),
      "notes": qsTr("Notes"),
      "email": qsTr("Email"),
      "card_number": qsTr("Card Number"),
      "cvv": qsTr("CVV"),
      "totp": qsTr("TOTP")
    };
    return labels[key] || key.charAt(0).toUpperCase() + key.slice(1).replace(/_/g, " ");
  }

  function itemTypeIcon(typeId) {
    switch(typeId) {
      case "login": return "dialog-password"
      case "note": return "text-x-generic"
      case "card": return "view-bank-card"
      default: return "document-new"
    }
  }

  function categoryColor(categoryId) {
    switch(categoryId) {
      case "all": return K.Theme.highlightColor
      case "favorites": return K.Theme.neutralTextColor
      case "trash": return K.Theme.disabledTextColor
      case "login": return K.Theme.highlightColor
      case "note": return K.Theme.neutralTextColor
      case "card": return K.Theme.negativeTextColor
      case "identity": return K.Theme.focusColor
      case "api": return K.Theme.linkColor
      case "kv": return K.Theme.linkColor
      case "infra":
      case "ssh_key":
      case "database":
      case "cloud_iam":
      case "file_secret":
      case "server_credentials": return K.Theme.positiveTextColor
      case "security": return K.Theme.negativeTextColor
      default: return K.Theme.textColor
    }
  }

  function itemTypeColor(typeId) {
    switch(typeId) {
      case "login": return K.Theme.highlightColor
      case "note": return K.Theme.neutralTextColor
      case "card": return K.Theme.negativeTextColor
      case "identity": return K.Theme.focusColor
      case "api": return K.Theme.linkColor
      case "kv": return K.Theme.linkColor
      case "ssh_key":
      case "database":
      case "cloud_iam":
      case "file_secret":
      case "server_credentials": return K.Theme.positiveTextColor
      default: return K.Theme.disabledTextColor
    }
  }

  function formatTimestamp(iso) {
    if (!iso) return ""
    return new Date(iso).toLocaleString(Qt.locale(), Locale.ShortFormat)
  }

  function formatAsEnv(fields) {
    return fields.map(function(f) {
      return f.key.toUpperCase() + '="' + (f.value || "").replace(/"/g, '\\"') + '"'
    }).join("\n")
  }

  function formatAsJson(fields) {
    var obj = {}
    fields.forEach(function(f) {
      obj[f.key] = f.value
    })
    return JSON.stringify(obj, null, 2)
  }

  AppModel {
    id: appModel
    objectName: "appModel"
  }

  Connections {
    target: appModel
    function onSelected_item_id_changed() {
      root.revealedFields = ({});
      root.copiedFieldKey = "";
    }
  }

  Timer {
    id: copiedTimer
    interval: 2000
    onTriggered: root.copiedFieldKey = ""
  }

  Component {
    id: passwordFieldComponent
    RowLayout {
      spacing: K.Units.smallSpacing
      property bool revealed: root.revealedFields[fieldData.key] === true
      K.SelectableLabel {
        id: passwordLabel
        text: parent.revealed ? fieldData.value : "••••••••••••"
        font.family: parent.revealed ? "monospace" : ""
        Layout.fillWidth: true
      }
      ToolButton {
        icon.name: parent.revealed ? "password-show-off" : "password-show-on"
        ToolTip.text: parent.revealed ? qsTr("Hide") : qsTr("Show")
        ToolTip.visible: hovered
        ToolTip.delay: 500
        onClicked: {
          var newState = Object.assign({}, root.revealedFields);
          newState[fieldData.key] = !newState[fieldData.key];
          root.revealedFields = newState;
        }
      }
      ToolButton {
        icon.name: root.copiedFieldKey === fieldData.key ? "checkmark" : "edit-copy"
        ToolTip.text: root.copiedFieldKey === fieldData.key ? qsTr("Copied!") : qsTr("Copy")
        ToolTip.visible: hovered
        ToolTip.delay: 500
        onClicked: {
          appModel.copy_to_clipboard(fieldData.value);
          root.copiedFieldKey = fieldData.key;
          copiedTimer.restart();
        }
      }
    }
  }

  Component {
    id: urlFieldComponent
    RowLayout {
      spacing: K.Units.smallSpacing
      K.SelectableLabel {
        text: fieldData.value
        color: K.Theme.linkColor
        Layout.fillWidth: true
        MouseArea {
          anchors.fill: parent
          cursorShape: Qt.PointingHandCursor
          onClicked: Qt.openUrlExternally(fieldData.value)
        }
      }
      ToolButton {
        icon.name: "internet-web-browser"
        ToolTip.text: qsTr("Open in browser")
        ToolTip.visible: hovered
        ToolTip.delay: 500
        onClicked: Qt.openUrlExternally(fieldData.value)
      }
      ToolButton {
        icon.name: root.copiedFieldKey === fieldData.key ? "checkmark" : "edit-copy"
        ToolTip.text: root.copiedFieldKey === fieldData.key ? qsTr("Copied!") : qsTr("Copy")
        ToolTip.visible: hovered
        ToolTip.delay: 500
        onClicked: {
          appModel.copy_to_clipboard(fieldData.value);
          root.copiedFieldKey = fieldData.key;
          copiedTimer.restart();
        }
      }
    }
  }

  Component {
    id: textFieldComponent
    RowLayout {
      spacing: K.Units.smallSpacing
      K.SelectableLabel {
        text: fieldData.value
        Layout.fillWidth: true
      }
      ToolButton {
        icon.name: root.copiedFieldKey === fieldData.key ? "checkmark" : "edit-copy"
        ToolTip.text: root.copiedFieldKey === fieldData.key ? qsTr("Copied!") : qsTr("Copy")
        ToolTip.visible: hovered
        ToolTip.delay: 500
        visible: fieldData.copyable
        onClicked: {
          appModel.copy_to_clipboard(fieldData.value);
          root.copiedFieldKey = fieldData.key;
          copiedTimer.restart();
        }
      }
    }
  }

  Component {
    id: noteFieldComponent
    ScrollView {
      Layout.fillWidth: true
      Layout.preferredHeight: Math.min(contentHeight + K.Units.largeSpacing, 150)
      TextArea {
        text: fieldData.value
        readOnly: true
        wrapMode: TextArea.Wrap
        selectByMouse: true
        background: Rectangle {
          color: K.Theme.backgroundColor
          border.color: K.Theme.separatorColor || K.Theme.textColor
          border.width: 1
          radius: 4
        }
      }
    }
  }

  Component {
    id: otpFieldComponent
    RowLayout {
      id: otpRow
      spacing: K.Units.smallSpacing
      property string totpSecret: fieldData.value
      property var totpResult: null

      Timer {
        id: totpTimer
        interval: 1000
        running: true
        repeat: true
        triggeredOnStart: true
        onTriggered: {
          var result = appModel.generate_totp(otpRow.totpSecret, "SHA1", 6, 30)
          if (result && result.length > 0) {
            try {
              otpRow.totpResult = JSON.parse(result)
            } catch (e) {
              otpRow.totpResult = null
            }
          } else {
            otpRow.totpResult = null
          }
          countdown.requestPaint()
        }
      }

      // Circular countdown indicator
      Rectangle {
        width: 32
        height: 32
        radius: 16
        color: "transparent"

        Canvas {
          id: countdown
          anchors.fill: parent
          onPaint: {
            var ctx = getContext("2d")
            ctx.reset()

            var centerX = width / 2
            var centerY = height / 2
            var radius = Math.min(width, height) / 2 - 3

            // Background circle
            ctx.beginPath()
            ctx.arc(centerX, centerY, radius, 0, 2 * Math.PI)
            ctx.strokeStyle = K.Theme.disabledTextColor
            ctx.lineWidth = 3
            ctx.stroke()

            // Progress arc
            if (otpRow.totpResult) {
              var progress = otpRow.totpResult.remaining / otpRow.totpResult.period
              var startAngle = -Math.PI / 2
              var endAngle = startAngle + (2 * Math.PI * progress)

              ctx.beginPath()
              ctx.arc(centerX, centerY, radius, startAngle, endAngle)
              ctx.strokeStyle = progress > 0.2 ? K.Theme.highlightColor : K.Theme.negativeTextColor
              ctx.lineWidth = 3
              ctx.stroke()
            }
          }
        }

        Label {
          anchors.centerIn: parent
          text: otpRow.totpResult ? otpRow.totpResult.remaining : ""
          font.pointSize: 9
          font.bold: true
          color: otpRow.totpResult && otpRow.totpResult.remaining <= 5 ? K.Theme.negativeTextColor : K.Theme.textColor
        }
      }

      Label {
        text: otpRow.totpResult ? otpRow.totpResult.code.replace(/(.{3})/, "$1 ") : "--- ---"
        font.family: "monospace"
        font.pointSize: 16
        font.bold: true
        color: otpRow.totpResult ? K.Theme.textColor : K.Theme.disabledTextColor
      }

      ToolButton {
        icon.name: root.copiedFieldKey === fieldData.key ? "checkmark" : "edit-copy"
        enabled: !!otpRow.totpResult
        ToolTip.text: root.copiedFieldKey === fieldData.key ? qsTr("Copied!") : qsTr("Copy")
        ToolTip.visible: hovered
        ToolTip.delay: 500
        onClicked: {
          if (otpRow.totpResult) {
            appModel.copy_to_clipboard(otpRow.totpResult.code)
            root.copiedFieldKey = fieldData.key
            copiedTimer.restart()
          }
        }
      }
    }
  }

  Component {
    id: fieldRowDelegate
    RowLayout {
      width: parent ? parent.width : implicitWidth
      spacing: K.Units.largeSpacing
      property var field: modelData

      Label {
        text: field.label.toUpperCase()
        font.family: "monospace"
        font.pointSize: 10
        Layout.preferredWidth: 140
        Layout.alignment: Qt.AlignVCenter
        color: K.Theme.disabledTextColor
      }

      Loader {
        Layout.fillWidth: true
        sourceComponent: {
          switch(field.kind) {
            case "password": return passwordFieldComponent
            case "url": return urlFieldComponent
            case "otp": return otpFieldComponent
            case "note": return noteFieldComponent
            default: return textFieldComponent
          }
        }
        property var fieldData: field
      }
    }
  }

  property string currentCategory: "all"
  property string selectedFolder: ""
  onCurrentCategoryChanged: appModel.current_category = currentCategory
  onSelectedFolderChanged: appModel.selected_folder = selectedFolder
  Component.onCompleted: {
    appModel.current_category = currentCategory
    appModel.selected_folder = selectedFolder
  }

  Component {
    id: folderNodeDelegate

    ColumnLayout {
      property var node: modelData
      property int depth: (parent && parent.depth !== undefined) ? parent.depth + 1 : 0
      Layout.fillWidth: true

      ItemDelegate {
        Layout.fillWidth: true
        leftPadding: K.Units.largeSpacing + depth * K.Units.gridUnit
        highlighted: root.selectedFolder === node.path
        onClicked: root.selectedFolder = node.path
        K.Theme.colorSet: highlighted ? K.Theme.Selection : K.Theme.Window
        K.Theme.inherit: false
        contentItem: RowLayout {
          spacing: K.Units.smallSpacing
          KD.IconTitleSubtitle {
            Layout.fillWidth: true
            title: node.name
            icon.name: "folder-symbolic"
            icon.color: K.Theme.neutralTextColor
            icon.width: K.Units.iconSizes.small
          }
          Label {
            text: node.total_count
            color: root.selectedFolder === node.path
              ? K.Theme.textColor
              : K.Theme.disabledTextColor
            font: K.Theme.smallFont
          }
        }
      }

      Repeater {
        model: node.children || []
        delegate: folderNodeDelegate
      }
    }
  }

  header: ToolBar {
    RowLayout {
      anchors.fill: parent
      spacing: K.Units.smallSpacing

      K.SearchField {
        Layout.fillWidth: true
        Layout.maximumWidth: 400
        placeholderText: qsTr("Search items...")
        text: appModel.search_query
        onTextChanged: appModel.search_query = text
        enabled: root.appState === "main"
      }

      Item { Layout.fillWidth: true }

      ToolButton {
        icon.name: "configure"
        ToolTip.text: qsTr("Settings")
        ToolTip.visible: hovered
        ToolTip.delay: 1000
        enabled: root.appState === "main"
        onClicked: pageStack.push(settingsPage)
      }

      ToolButton {
        icon.name: "system-lock-screen"
        ToolTip.text: qsTr("Lock vault")
        ToolTip.visible: hovered
        ToolTip.delay: 1000
        enabled: root.appState === "main"
        onClicked: appModel.lock()
      }
    }
  }

  pageStack.initialPage: K.Page {
    id: mainPage
    title: ""

    SplitView {
      id: mainSplitView
      anchors.fill: parent
      orientation: Qt.Horizontal

      handle: Rectangle {
        implicitWidth: K.Units.smallSpacing
        color: SplitHandle.pressed ? K.Theme.highlightColor
             : SplitHandle.hovered ? K.Theme.hoverColor
             : "transparent"

        Rectangle {
          anchors.centerIn: parent
          width: 2
          height: parent.height * 0.2
          radius: 1
          color: K.Theme.disabledTextColor
          opacity: SplitHandle.hovered ? 1 : 0.5
        }
      }

      Frame {
        SplitView.preferredWidth: 260
        SplitView.minimumWidth: 240
        SplitView.maximumWidth: 320

        ColumnLayout {
          anchors.fill: parent
          spacing: 0

          // Panel header with branding and storage selector
          RowLayout {
            Layout.fillWidth: true
            Layout.margins: K.Units.smallSpacing
            spacing: K.Units.smallSpacing

            K.Icon {
              source: "security-high"
              Layout.preferredWidth: K.Units.iconSizes.medium
              Layout.preferredHeight: K.Units.iconSizes.medium
            }

            Label {
              text: "Zann"
              font.pointSize: 14
              font.bold: true
            }

            Item { Layout.fillWidth: true }

            Button {
              id: storageButton
              text: appModel.storages[appModel.current_storage_index] || qsTr("Select storage")
              icon.name: "network-server"
              onClicked: storageMenu.open()

              Menu {
                id: storageMenu
                y: storageButton.height

                Repeater {
                  model: appModel.storages
                  MenuItem {
                    text: modelData
                    checkable: true
                    checked: index === appModel.current_storage_index
                    onTriggered: appModel.current_storage_index = index
                  }
                }
              }
            }
          }

          K.Separator { Layout.fillWidth: true }

          ScrollView {
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            contentWidth: availableWidth

            ColumnLayout {
              anchors.left: parent.left
              anchors.right: parent.right
              anchors.margins: K.Units.largeSpacing
              spacing: K.Units.largeSpacing

              K.Heading { text: qsTr("Vaults"); level: 3; Layout.fillWidth: true }

            ListView {
              width: parent.width
              Layout.fillWidth: true
              height: contentHeight
              interactive: false
              clip: true
              spacing: K.Units.smallSpacing
              model: appModel.vaults
              currentIndex: appModel.current_vault_index
              delegate: KD.SubtitleDelegate {
                width: ListView.view.width
                text: modelData
                icon.name: "security-high"
                highlighted: ListView.view.currentIndex === index
                onClicked: ListView.view.currentIndex = index
                K.Theme.colorSet: highlighted ? K.Theme.Selection : K.Theme.Window
                K.Theme.inherit: false
              }
              onCurrentIndexChanged: {
                if (appModel.current_vault_index !== currentIndex) {
                  appModel.current_vault_index = currentIndex
                }
              }
            }

            K.Separator { Layout.fillWidth: true }

            Item { height: K.Units.largeSpacing }

            K.Heading { text: qsTr("Categories"); level: 3; Layout.fillWidth: true }

            ColumnLayout {
              Layout.fillWidth: true
              spacing: K.Units.smallSpacing

              Repeater {
                model: root.categoriesData
                delegate: ItemDelegate {
                  Layout.fillWidth: true
                  highlighted: root.currentCategory === modelData.id
                  onClicked: root.currentCategory = modelData.id
                  K.Theme.colorSet: highlighted ? K.Theme.Selection : K.Theme.Window
                  K.Theme.inherit: false
                  contentItem: RowLayout {
                    spacing: K.Units.smallSpacing
                    KD.IconTitleSubtitle {
                      Layout.fillWidth: true
                      title: modelData.label
                      icon.name: modelData.icon || "folder-symbolic"
                      icon.color: root.categoryColor(modelData.id)
                      icon.width: K.Units.iconSizes.small
                    }
                    Label {
                      text: modelData.count
                      color: highlighted ? K.Theme.textColor : K.Theme.disabledTextColor
                      font: K.Theme.smallFont
                    }
                  }
                }
              }
            }

            Item { height: K.Units.largeSpacing }

            K.Heading { text: qsTr("Folders"); level: 3; Layout.fillWidth: true }

            ColumnLayout {
              Layout.fillWidth: true
              spacing: K.Units.smallSpacing

              ItemDelegate {
                id: noFolderDelegate
                Layout.fillWidth: true
                highlighted: root.selectedFolder === "__no_folder__"
                onClicked: root.selectedFolder = "__no_folder__"
                K.Theme.colorSet: highlighted ? K.Theme.Selection : K.Theme.Window
                K.Theme.inherit: false
                contentItem: RowLayout {
                  spacing: K.Units.smallSpacing
                  KD.IconTitleSubtitle {
                    Layout.fillWidth: true
                    title: qsTr("No folder")
                    icon.name: "folder-root-symbolic"
                    icon.width: K.Units.iconSizes.small
                  }
                  Label {
                    text: root.foldersData.items_without_folder || 0
                    color: noFolderDelegate.highlighted ? K.Theme.textColor : K.Theme.disabledTextColor
                    font: K.Theme.smallFont
                  }
                }
              }

              Repeater {
                model: root.foldersData.tree || []
                delegate: folderNodeDelegate
              }
            }  // Close Folders ColumnLayout
          }  // Close inner ColumnLayout
        }  // Close ScrollView
        }  // Close outer ColumnLayout
      }  // Close Frame

      Frame {
        SplitView.preferredWidth: 420
        SplitView.minimumWidth: 360
        SplitView.maximumWidth: 640

        ColumnLayout {
          anchors.fill: parent
          spacing: 0

          // Panel header with category info and actions
          RowLayout {
            Layout.fillWidth: true
            Layout.margins: K.Units.smallSpacing
            spacing: K.Units.smallSpacing

            // Left: Category label + count
            ColumnLayout {
              spacing: 2

              Label {
                property var currentCat: root.categoriesData.find(function(c) { return c.id === root.currentCategory; })
                text: currentCat ? currentCat.label : qsTr("All Items")
                font.bold: true
              }

              Label {
                text: qsTr("%1 items").arg(root.filteredItemsCount)
                font: K.Theme.smallFont
                color: K.Theme.disabledTextColor
              }
            }

            Item { Layout.fillWidth: true }

            // Right: Actions
            ToolButton {
              icon.name: "view-sort"
              ToolTip.text: qsTr("Sort")
              ToolTip.visible: hovered
              ToolTip.delay: 500
            }

            ToolButton {
              icon.name: "list-add"
              ToolTip.text: qsTr("Create item")
              ToolTip.visible: hovered
              ToolTip.delay: 500
            }

            ToolButton {
              icon.name: "trash-empty"
              visible: root.currentCategory === "trash"
              ToolTip.text: qsTr("Empty trash")
              ToolTip.visible: hovered
              ToolTip.delay: 500
            }
          }

          K.Separator { Layout.fillWidth: true }

          Item {
            Layout.fillWidth: true
            Layout.fillHeight: true

            ListView {
              anchors.fill: parent
              clip: true
              model: root.filteredItemsCount
              onAtYEndChanged: {
                if (atYEnd && appModel.items_has_more && !root.loadingMore) {
                  root.loadingMore = true
                  appModel.load_more_items()
                }
              }
              footer: Item {
                width: ListView.view.width
                height: root.loadingMore ? K.Units.gridUnit * 3 : 0
                visible: root.loadingMore

                BusyIndicator {
                  anchors.centerIn: parent
                  running: root.loadingMore
                }
              }
              delegate: KD.SubtitleDelegate {
                width: ListView.view.width
                property var itemData: root.itemAt(index)
                text: itemData ? itemData.title : ""
                subtitle: itemData ? itemData.path : ""
                icon.name: itemData ? root.itemTypeIcon(itemData.type_id) : ""
                icon.color: itemData ? root.itemTypeColor(itemData.type_id) : K.Theme.textColor
                highlighted: itemData ? itemData.id === appModel.selected_item_id : false
                onClicked: {
                  if (itemData) {
                    appModel.select_item(itemData.id)
                  }
                }
                K.Theme.colorSet: highlighted ? K.Theme.Selection : K.Theme.View
                K.Theme.inherit: false
              }
            }

            K.PlaceholderMessage {
              anchors.centerIn: parent
              width: Math.min(360, parent.width - K.Units.gridUnit * 4)
              visible: !root.loadingMore && root.filteredItemsCount === 0
              icon.name: "list-add"
              text: appModel.search_query.length > 0
                ? qsTr("No results")
                : (root.currentCategory === "trash" ? qsTr("Trash is empty") : qsTr("No items yet"))
              explanation: appModel.search_query.length > 0
                ? qsTr("Try a different search term.")
                : qsTr("Create your first item to get started.")
            }
          }
        }
      }

      Frame {
        SplitView.preferredWidth: 380
        SplitView.minimumWidth: 320
        SplitView.fillWidth: true
        visible: !root.isNarrow

        ColumnLayout {
          anchors.fill: parent
          spacing: 0

          // Panel header with vault badge, breadcrumbs, and actions
          RowLayout {
            Layout.fillWidth: true
            Layout.margins: K.Units.smallSpacing
            spacing: K.Units.smallSpacing
            visible: !!root.selectedItemData

            // Vault badge
            Rectangle {
              implicitWidth: vaultLabel.implicitWidth + K.Units.smallSpacing * 2
              implicitHeight: vaultLabel.implicitHeight + K.Units.smallSpacing
              color: K.Theme.highlightColor
              radius: 4

              Label {
                id: vaultLabel
                anchors.centerIn: parent
                text: appModel.vaults[appModel.current_vault_index] || ""
                color: K.Theme.highlightedTextColor
                font: K.Theme.smallFont
              }
            }

            // Breadcrumb path
            Label {
              text: root.selectedItemData ? root.selectedItemData.path : ""
              color: K.Theme.disabledTextColor
              font: K.Theme.smallFont
              elide: Text.ElideMiddle
              Layout.fillWidth: true
            }

            // Actions
            ToolButton {
              icon.name: "clock"
              ToolTip.text: qsTr("View history")
              ToolTip.visible: hovered
              ToolTip.delay: 500
              enabled: false  // Placeholder - history not yet implemented
            }

            ToolButton {
              icon.name: "document-edit"
              ToolTip.text: root.selectedItemData && root.selectedItemData.deleted ? qsTr("Restore") : qsTr("Edit")
              ToolTip.visible: hovered
              ToolTip.delay: 500
            }

            ToolButton {
              id: moreActionsButton
              icon.name: "overflow-menu"
              ToolTip.text: qsTr("More actions")
              ToolTip.visible: hovered
              ToolTip.delay: 500
              onClicked: itemActionsMenu.open()

              Menu {
                id: itemActionsMenu
                y: moreActionsButton.height

                MenuItem {
                  text: qsTr("Copy as ENV")
                  icon.name: "edit-copy"
                  onTriggered: {
                    appModel.copy_to_clipboard(root.formatAsEnv(root.payloadFields))
                  }
                }
                MenuItem {
                  text: qsTr("Copy as JSON")
                  icon.name: "edit-copy"
                  onTriggered: {
                    appModel.copy_to_clipboard(root.formatAsJson(root.payloadFields))
                  }
                }
                MenuSeparator {}
                MenuItem {
                  text: qsTr("Duplicate")
                  icon.name: "edit-copy"
                }
                MenuItem {
                  text: qsTr("Move to folder...")
                  icon.name: "folder-move"
                }
                MenuSeparator {}
                MenuItem {
                  text: root.selectedItemData && root.selectedItemData.deleted ? qsTr("Restore") : qsTr("Move to trash")
                  icon.name: root.selectedItemData && root.selectedItemData.deleted ? "view-refresh" : "user-trash"
                  visible: !(root.selectedItemData && root.selectedItemData.deleted)
                }
                MenuItem {
                  text: qsTr("Delete forever")
                  icon.name: "edit-delete"
                  visible: !!(root.selectedItemData && root.selectedItemData.deleted)
                }
              }
            }
          }

          K.Separator {
            Layout.fillWidth: true
            visible: !!root.selectedItemData
          }

          Item {
            Layout.fillWidth: true
            Layout.fillHeight: true

            ColumnLayout {
              anchors.fill: parent
              anchors.margins: K.Units.largeSpacing
              spacing: K.Units.largeSpacing

              K.PlaceholderMessage {
                visible: !root.selectedItemData
                text: qsTr("Select an item")
                icon.name: "document-preview"
              }

              ColumnLayout {
                visible: !!root.selectedItemData
                spacing: K.Units.largeSpacing

                // Item type avatar + title + timestamp
                RowLayout {
                  Layout.fillWidth: true
                  spacing: K.Units.largeSpacing

                  // Type avatar
                  Rectangle {
                    width: K.Units.gridUnit * 3
                    height: width
                    radius: width / 2
                    color: root.selectedItemData ? root.itemTypeColor(root.selectedItemData.type_id) : K.Theme.disabledTextColor

                    Label {
                      anchors.centerIn: parent
                      text: root.selectedItemData && root.selectedItemData.title ? root.selectedItemData.title.charAt(0).toUpperCase() : ""
                      font.pointSize: 16
                      font.bold: true
                      color: "white"
                    }
                  }

                  // Title + timestamp
                  ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 2

                    Label {
                      text: root.selectedItemData ? root.selectedItemData.title : ""
                      font.pointSize: 18
                      font.bold: true
                      wrapMode: Text.Wrap
                      Layout.fillWidth: true
                    }

                    Label {
                      text: root.selectedItemData ? root.formatTimestamp(root.selectedItemData.updated_at) : ""
                      font: K.Theme.smallFont
                      color: K.Theme.disabledTextColor
                    }
                  }
                }

                K.Heading {
                  text: qsTr("Fields")
                  level: 4
                  visible: root.payloadFields.length > 0
                }

                ScrollView {
                  Layout.fillWidth: true
                  Layout.fillHeight: true
                  clip: true
                  contentWidth: availableWidth
                  visible: root.payloadFields.length > 0

                  ColumnLayout {
                    width: parent.width
                    spacing: K.Units.largeSpacing

                    Repeater {
                      model: root.payloadFields
                      delegate: fieldRowDelegate
                    }
                  }
                }

                K.PlaceholderMessage {
                  visible: root.payloadFields.length === 0 && !!root.selectedItemData
                  text: qsTr("No fields")
                  icon.name: "view-list-details"
                  Layout.fillWidth: true
                  Layout.fillHeight: true
                }
              }
            }
          }
        }
      }
    }
  }

  Component {
    id: settingsPage

    K.Page {
      title: qsTr("Settings")

      actions: [
        K.Action {
          icon.name: "go-previous"
          text: qsTr("Back")
          onTriggered: pageStack.pop()
        }
      ]

      ColumnLayout {
        anchors.fill: parent
        anchors.margins: K.Units.largeSpacing
        spacing: K.Units.largeSpacing * 2

        K.Heading { text: qsTr("Appearance"); level: 3 }

        K.FormLayout {
          Layout.fillWidth: true

          Switch {
            K.FormData.label: qsTr("Dense mode")
            text: qsTr("Compact spacing")
            checked: false
          }
        }

        K.Heading { text: qsTr("Theme"); level: 4 }

        ButtonGroup { id: themeGroup }

        RowLayout {
          spacing: K.Units.largeSpacing
          RadioButton { text: qsTr("System"); checked: true; ButtonGroup.group: themeGroup }
          RadioButton { text: qsTr("Light"); ButtonGroup.group: themeGroup }
          RadioButton { text: qsTr("Dark"); ButtonGroup.group: themeGroup }
        }

        K.Separator { Layout.fillWidth: true }

        K.Heading { text: qsTr("Security"); level: 3 }

        K.FormLayout {
          Layout.fillWidth: true

          Switch {
            K.FormData.label: qsTr("Unlock")
            text: qsTr("Require unlock on startup")
            checked: true
          }
        }

        K.Heading { text: qsTr("Clipboard timeout"); level: 4 }

        ButtonGroup { id: clipGroup }

        ColumnLayout {
          spacing: K.Units.smallSpacing
          RadioButton { text: qsTr("Never"); checked: true; ButtonGroup.group: clipGroup }
          RadioButton { text: qsTr("15 seconds"); ButtonGroup.group: clipGroup }
          RadioButton { text: qsTr("30 seconds"); ButtonGroup.group: clipGroup }
          RadioButton { text: qsTr("60 seconds"); ButtonGroup.group: clipGroup }
        }
      }
    }
  }

  // Welcome Page - shown on first run
  Rectangle {
    id: welcomeOverlay
    anchors.fill: parent
    visible: root.appState === "welcome"
    z: 1000
    color: Qt.rgba(K.Theme.backgroundColor.r, K.Theme.backgroundColor.g, K.Theme.backgroundColor.b, 0.95)

    MouseArea {
      anchors.fill: parent
      acceptedButtons: Qt.AllButtons
    }

    WelcomePage {
      anchors.fill: parent
      onStartLocalSetup: appModel.start_local_setup()
      onStartConnect: appModel.start_connect()
    }
  }

  // Password Setup Page - create master password
  Rectangle {
    id: passwordSetupOverlay
    anchors.fill: parent
    visible: root.appState === "password"
    z: 1000
    color: Qt.rgba(K.Theme.backgroundColor.r, K.Theme.backgroundColor.g, K.Theme.backgroundColor.b, 0.95)

    MouseArea {
      anchors.fill: parent
      acceptedButtons: Qt.AllButtons
    }

    PasswordSetup {
      anchors.fill: parent
      setupError: appModel.setup_error
      setupBusy: appModel.setup_busy
      passwordMode: appModel.setup_password_mode
      onCreatePassword: function(password, confirm) {
        appModel.create_master_password(password, confirm)
      }
      onBack: appModel.back_to_welcome()
    }
  }

  // Server Connect Page - OIDC flow (Phase 2)
  Rectangle {
    id: connectOverlay
    anchors.fill: parent
    visible: root.appState === "connect"
    z: 1000
    color: Qt.rgba(K.Theme.backgroundColor.r, K.Theme.backgroundColor.g, K.Theme.backgroundColor.b, 0.95)

    MouseArea {
      anchors.fill: parent
      acceptedButtons: Qt.AllButtons
    }

    ServerConnect {
      anchors.fill: parent
      serverUrl: appModel.connect_server_url
      connectStatus: appModel.connect_status
      connectError: appModel.connect_error
      connectBusy: appModel.connect_busy
      connectLoginId: appModel.connect_login_id
      connectVerification: appModel.connect_verification
      connectOldFp: appModel.connect_old_fp
      connectNewFp: appModel.connect_new_fp
      connectMethods: appModel.connect_methods
      connectPasswordMode: appModel.connect_password_mode
      onServerUrlEdited: function(value) { appModel.connect_server_url = value }
      onBeginConnect: appModel.begin_server_connect()
      onConnectOidc: appModel.connect_with_oidc()
      onConnectPassword: function(email, password, fullName, mode) {
        appModel.connect_with_password(email, password, fullName, mode)
      }
      onTrustFingerprint: appModel.trust_fingerprint()
      onPollOidc: appModel.poll_oidc_status()
      onBack: appModel.back_to_welcome()
    }
  }

  // Unlock Overlay - shown when vault exists but is locked
  Rectangle {
    id: unlockOverlay
    anchors.fill: parent
    visible: root.appState === "unlock"
    z: 1000
    color: Qt.rgba(K.Theme.backgroundColor.r, K.Theme.backgroundColor.g, K.Theme.backgroundColor.b, 0.85)

    MouseArea {
      anchors.fill: parent
      acceptedButtons: Qt.AllButtons
    }

    Frame {
      width: Math.min(420, root.width - K.Units.gridUnit * 4)
      anchors.centerIn: parent
      padding: K.Units.largeSpacing * 2

      ColumnLayout {
        anchors.left: parent.left
        anchors.right: parent.right
        spacing: K.Units.largeSpacing

        K.Icon {
          source: "security-high"
          Layout.preferredWidth: K.Units.iconSizes.huge
          Layout.preferredHeight: K.Units.iconSizes.huge
          Layout.alignment: Qt.AlignHCenter
        }

        K.Heading {
          text: qsTr("Unlock Vault")
          level: 2
          Layout.alignment: Qt.AlignHCenter
        }

        Label {
          text: qsTr("Enter your master password to unlock.")
          wrapMode: Text.Wrap
          Layout.fillWidth: true
          horizontalAlignment: Text.AlignHCenter
          color: K.Theme.disabledTextColor
        }

        TextField {
          id: passwordInput
          objectName: "unlockPasswordInput"
          echoMode: TextInput.Password
          placeholderText: qsTr("Master password")
          Layout.fillWidth: true
          onAccepted: appModel.unlock(text)
        }

        K.InlineMessage {
          Layout.fillWidth: true
          visible: appModel.status.length > 0 && appModel.status !== "Locked"
          type: appModel.status === "invalid password" ? K.MessageType.Error : K.MessageType.Information
          text: appModel.status
        }

        RowLayout {
          Layout.fillWidth: true
          spacing: K.Units.largeSpacing

          Item { Layout.fillWidth: true }

          Button {
            objectName: "unlockSubmitButton"
            text: qsTr("Unlock")
            icon.name: "object-unlocked"
            onClicked: appModel.unlock(passwordInput.text)
          }
        }
      }
    }
  }

  // Loading Overlay - shown during app initialization
  Rectangle {
    id: loadingOverlay
    anchors.fill: parent
    visible: root.appState === "loading"
    z: 1000
    color: K.Theme.backgroundColor

    ColumnLayout {
      anchors.centerIn: parent
      spacing: K.Units.largeSpacing

      BusyIndicator {
        Layout.alignment: Qt.AlignHCenter
        running: loadingOverlay.visible
      }

      Label {
        text: qsTr("Loading...")
        Layout.alignment: Qt.AlignHCenter
        color: K.Theme.disabledTextColor
      }
    }
  }

}

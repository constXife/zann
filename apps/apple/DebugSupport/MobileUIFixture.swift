#if DEBUG && ZANN_UI_FIXTURE_HOST && os(iOS)
import Foundation
import SwiftUI
import ZannCoreKit

/// Explicit UI-test entry point, excluded from Release. Uses the existing
/// Rust fixture and test ports in a fresh temporary root, never user storage.
@MainActor
enum MobileUIFixture {
    @ViewBuilder static func root(_ content: MobileRootView) -> some View {
        if ProcessInfo.processInfo.arguments.contains("--mobile-ui-large-text") {
            content.dynamicTypeSize(.accessibility5)
        } else {
            content
        }
    }
    static let password = "synthetic mobile UI fixture"
    static func makeModel() -> AppModel {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let model = AppModel(opening: {
            let keystore = MemoryKeystore()
            let core = try createCore(dbPath: root.appendingPathComponent("local.sqlite").path,
                                      keystore: keystore, secretStore: MemorySecretStore())
            _ = try core.seedOfflineFixture(password: password)
            guard let otp = itemTypeSchemas().first(where: { $0.typeId == "login" })?.advanced.first(where: { $0.kind == .otp }) else {
                throw CoreError.InvalidArgument("UI fixture requires the login schema's OTP field")
            }
            for index in (0..<40).reversed() {
                let title = index == 0 ? "Example account" : String(format: "Sample %02d", index)
                let draft = try ItemDraftFfi.create(typeId: "login")
                try draft.setLocation(name: title, folder: "Examples")
                for (position, field) in draft.fields().enumerated() {
                    switch field.key {
                    case "username": try draft.setFieldValue(index: UInt64(position), value: "alex@example.test")
                    case "password": try draft.setFieldValue(index: UInt64(position), value: "synthetic-password")
                    case "url": try draft.setFieldValue(index: UInt64(position), value: "https://example.test")
                    default: break
                    }
                }
                if index == 0 {
                    let position = UInt64(draft.fields().count)
                    draft.addField()
                    try draft.setFieldKey(index: position, key: otp.key)
                    try draft.setFieldKind(index: position, kind: otp.kind)
                    try draft.setFieldValue(index: position, value: "JBSWY3DPEHPK3PXP")
                }
                _ = try core.itemCreate(create: draft.createRequest())
            }
            _ = try core.lock()
            return (core, keystore)
        }, preferences: { PreferencesFile(url: root.appendingPathComponent("preferences.json")) },
        systemLanguage: "en", browser: .loopback(open: { _ in }))
        model.updatePreferences { $0.lockOnFocusLoss = false }
        Task { await model.submit(password: password, mode: .unlock) }
        return model
    }
}
#endif

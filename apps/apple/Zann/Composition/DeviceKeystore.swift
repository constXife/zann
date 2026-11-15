import ZannCoreKit

/// The injected keystore port plus the app's localized biometric prompt.
protocol DeviceKeystore: PlatformKeystore {
    func setPromptReason(_ reason: String)
    func cancelUnlock()
}

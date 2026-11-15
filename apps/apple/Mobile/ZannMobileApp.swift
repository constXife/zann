import SwiftUI

/// Mobile entry point over the shared auth/unlock model and native adapters.
@main
@MainActor
enum ZannMobileMain {
    static func main() {
        #if DEBUG
        if ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] != nil {
            MobileTestHost.main()
            return
        }
        #endif
        ZannMobileApp.main()
    }
}

#if DEBUG
/// Unit tests own temporary cores; app startup must never open user storage.
private struct MobileTestHost: App {
    var body: some Scene { WindowGroup { EmptyView() } }
}
#endif

@MainActor
struct ZannMobileApp: App {
    @StateObject private var model: AppModel
    @StateObject private var lifecycle: MobileLifecycle

    init() {
        let web = WebAuthentication()
        let model: AppModel
        #if DEBUG && ZANN_UI_FIXTURE_HOST
        if ProcessInfo.processInfo.arguments.contains("--mobile-ui-fixture") {
            model = MobileUIFixture.makeModel()
        } else {
            model = MobileAppComposition.makeModel(webAuthentication: web)
        }
        #else
        model = MobileAppComposition.makeModel(webAuthentication: web)
        #endif
        _model = StateObject(wrappedValue: model)
        _lifecycle = StateObject(wrappedValue: MobileLifecycle(model: model, webAuthentication: web))
    }

    var body: some Scene {
        WindowGroup {
            #if DEBUG && ZANN_UI_FIXTURE_HOST
            MobileUIFixture.root(MobileRootView(model: model, lifecycle: lifecycle))
            #else
            MobileRootView(model: model, lifecycle: lifecycle)
            #endif
        }
    }
}

import AppKit
import Carbon
import Combine

/// Observes keyboard metadata only; never receives password contents or key events.
@MainActor
final class KeyboardInputSource: ObservableObject {
    struct Source {
        let language: String
        let name: String
    }

    @Published private(set) var current: Source?
    private var changes = Set<AnyCancellable>()

    init() {
        refresh()
        DistributedNotificationCenter.default()
            .publisher(for: Notification.Name(kTISNotifySelectedKeyboardInputSourceChanged as String))
            .receive(on: RunLoop.main)
            .sink { [weak self] _ in self?.refresh() }
            .store(in: &changes)
        NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)
            .sink { [weak self] _ in self?.refresh() }
            .store(in: &changes)
    }

    func refresh() {
        guard let source = TISCopyCurrentKeyboardInputSource()?.takeRetainedValue(),
              let languages = TISGetInputSourceProperty(source, kTISPropertyInputSourceLanguages),
              let name = TISGetInputSourceProperty(source, kTISPropertyLocalizedName),
              let language = (Unmanaged<CFArray>.fromOpaque(languages).takeUnretainedValue()
                as NSArray).firstObject as? String,
              !language.isEmpty,
              let code = Locale.Language(identifier: language).languageCode?.identifier else {
            current = nil
            return
        }
        current = Source(
            language: code.uppercased(),
            name: Unmanaged<CFString>.fromOpaque(name).takeUnretainedValue() as String
        )
    }
}

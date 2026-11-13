import Foundation
import ZannCoreKit

/// One open create or edit form over a zann-ui-core `ItemDraftFfi`. The draft
/// owns templates, validation and the payload; this type mirrors its fields
/// for SwiftUI and runs the blocking save off the main actor.
@MainActor
final class ItemEditorModel: ObservableObject, Identifiable {
    enum Mode: Equatable {
        case create
        case edit(id: String)
    }

    /// The item types a new draft can take, in schema order.
    private static let schemas = itemTypeSchemas()
    static let typeIDs = schemas.map(\.typeId)

    /// Every kind the draft accepts, in the order COSMIC lists them.
    static let kinds: [FieldKindFfi] = [.text, .password, .url, .otp, .note]

    let mode: Mode
    @Published var name: String
    @Published var folder: String
    @Published private(set) var typeID: String
    @Published private(set) var fields: [DraftFieldFfi]
    @Published private(set) var busy = false
    /// The draft error's translation key, or a core error's own message.
    @Published private(set) var error: EditorError?

    enum EditorError: Equatable {
        case translated(key: String)
        case message(String)
    }

    private let draft: ItemDraftFfi

    private var mainDefinitions: [FieldDefinitionFfi] {
        Self.schemas.first { $0.typeId == typeID }?.main ?? []
    }

    var mainFieldIndices: [Int] {
        mainDefinitions.compactMap { definition in fields.firstIndex { $0.key == definition.key } }
    }

    var additionalFieldIndices: [Int] {
        let main = Set(mainFieldIndices)
        return fields.indices.filter { !main.contains($0) }
    }

    var missingMainFields: [FieldDefinitionFfi] {
        mainDefinitions.filter { definition in !fields.contains { $0.key == definition.key } }
    }

    func label(for key: String) -> String? {
        mainDefinitions.first { $0.key == key }?.label
    }

    private init(mode: Mode, draft: ItemDraftFfi) {
        self.mode = mode
        self.draft = draft
        name = draft.name()
        folder = draft.folder() ?? ""
        typeID = draft.typeId()
        fields = draft.fields()
    }

    static func create(typeID: String) throws -> ItemEditorModel {
        ItemEditorModel(mode: .create, draft: try ItemDraftFfi.create(typeId: typeID))
    }

    static func edit(_ item: ItemDetail) throws -> ItemEditorModel {
        ItemEditorModel(mode: .edit(id: item.id), draft: try ItemDraftFfi.edit(detail: item))
    }

    func setType(_ value: String) {
        apply { _ = try draft.setType(typeId: value) }
    }

    func setKey(_ index: Int, _ value: String) {
        apply { try draft.setFieldKey(index: UInt64(index), key: value) }
    }

    func setValue(_ index: Int, _ value: String) {
        apply { try draft.setFieldValue(index: UInt64(index), value: value) }
    }

    func setKind(_ index: Int, _ kind: FieldKindFfi) {
        apply { try draft.setFieldKind(index: UInt64(index), kind: kind) }
    }

    func addField() {
        draft.addField()
        fields = draft.fields()
    }

    func addField(_ definition: FieldDefinitionFfi) {
        let index = fields.count
        addField()
        setKey(index, definition.key)
        setKind(index, definition.kind)
    }

    func removeField(_ index: Int) {
        apply { try draft.removeField(index: UInt64(index)) }
    }

    /// Validates, stores and returns the saved item; a failure stays in
    /// `error` and returns `nil`.
    func save(with core: CoreFacade) async -> ItemDetail? {
        guard !busy else { return nil }
        error = nil
        let store: @Sendable () throws -> ItemDetail
        do {
            try draft.setLocation(name: name, folder: folder)
            switch mode {
            case .create:
                let request = try draft.createRequest()
                store = { try core.itemCreate(create: request) }
            case .edit(let id):
                let request = try draft.updateRequest()
                store = { try core.itemUpdate(id: id, update: request) }
            }
        } catch {
            self.error = Self.editorError(error)
            return nil
        }
        busy = true
        defer { busy = false }
        let result = await Task.detached(priority: .userInitiated) { Result(catching: store) }.value
        switch result {
        case .success(let item):
            return item
        case .failure(let failure):
            error = Self.editorError(failure)
            return nil
        }
    }

    private func apply(_ edit: () throws -> Void) {
        do {
            try edit()
            error = nil
        } catch {
            self.error = Self.editorError(error)
        }
        typeID = draft.typeId()
        fields = draft.fields()
    }

    private static func editorError(_ error: Error) -> EditorError {
        if case .Draft(_, let translationKey, _) = error as? CoreError {
            return .translated(key: translationKey)
        }
        return .message(describe(error))
    }
}

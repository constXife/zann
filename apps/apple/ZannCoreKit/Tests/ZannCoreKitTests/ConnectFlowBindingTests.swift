import XCTest
@testable import ZannCoreKit

final class ConnectFlowBindingTests: XCTestCase {
    func testTypedConnectEffectsAndCompletionsCrossTheBinding() throws {
        let flow = ConnectFlowFfi()
        let effects = flow.dispatch(action: .probe(url: "https://fixture.example.test"))
        guard case .probe(let id, let url, let name, let profile)? = effects.last else {
            return XCTFail("typed probe effect")
        }
        XCTAssertEqual(url, "https://fixture.example.test")
        XCTAssertEqual(name, "Remote")
        XCTAssertEqual(profile, "default")
        XCTAssertTrue(flow.accepts(id: id, step: .probe))
        let next = flow.complete(completion: .probed(id: id, probe: .ready(info:
            ConnectServerFfi(methods: [.password], registrationAvailable: false, serverName: "Fixture"))))
        XCTAssertTrue(next.isEmpty)
        XCTAssertEqual(flow.snapshot().stage, .password(register: false))
        let login = flow.dispatch(action: .submitPassword(email: "person@example.test", password: "synthetic", fullName: nil))
        guard case .password(let loginID, _, _, _, false, _)? = login.first else {
            return XCTFail("typed password effect")
        }
        flow.dispatch(action: .cancel)
        XCTAssertFalse(flow.accepts(id: loginID, step: .password))
        XCTAssertTrue(flow.complete(completion: .password(id: loginID, storageId: "old", hasPersonalKeys: false)).isEmpty)
        XCTAssertEqual(flow.snapshot().stage, .closed)
    }
}

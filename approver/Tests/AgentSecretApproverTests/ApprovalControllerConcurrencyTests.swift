@testable import AgentSecretApprover
import Foundation
import XCTest

final class ApprovalControllerConcurrencyTests: XCTestCase {
    private struct NoopApprovalLogger: ApprovalLogger {
        func record(_: String, requestID _: String?) {
            /* Intentionally ignored. */
        }
    }

    private enum ThreadObservation {
        case unrecorded
        case main
        case background
    }

    private final class ThreadRecordingDaemonClient: ApprovalDaemonClient {
        private let lock = NSLock()
        private let request: ApprovalRequest
        private var fetchObservation: ThreadObservation = .unrecorded
        private var submitObservation: ThreadObservation = .unrecorded

        var fetchThreadObservation: ThreadObservation {
            lock.lock()
            defer { lock.unlock() }
            return fetchObservation
        }

        var submitThreadObservation: ThreadObservation {
            lock.lock()
            defer { lock.unlock() }
            return submitObservation
        }

        init(request: ApprovalRequest) {
            self.request = request
        }

        func fetchPendingRequest() -> ApprovalRequest {
            lock.lock()
            fetchObservation = Thread.isMainThread ? .main : .background
            lock.unlock()
            return request
        }

        func submit(_: ApprovalDecision) {
            lock.lock()
            submitObservation = Thread.isMainThread ? .main : .background
            lock.unlock()
        }

        deinit {
            /* Required by SwiftLint. */
        }
    }

    @MainActor
    private final class ThreadRecordingPresenter: ApprovalPresenter {
        private(set) var decideRanOnMainThread = false

        func decide(for _: ApprovalRequest) -> ApprovalDecisionKind {
            decideRanOnMainThread = Thread.isMainThread
            return .approveOnce
        }

        deinit {
            /* Required by SwiftLint. */
        }
    }

    private static var sampleRequest: ApprovalRequest {
        ApprovalRequest(
            requestID: "req_concurrency",
            nonce: "nonce_concurrency",
            reason: "Run concurrency check",
            command: ["/usr/bin/env", "true"],
            cwd: "/tmp/project",
            expiresAt: Date(timeIntervalSince1970: 1_800_000_000),
            secrets: [
                RequestedSecret(
                    alias: "EXAMPLE_TOKEN",
                    ref: "op://Example Vault/Example Item/token",
                    account: "Work"
                )
            ],
            resolvedExecutable: "/usr/bin/env"
        )
    }

    @MainActor
    func testDaemonClientRunsOffMainThreadWhilePresenterRunsOnMainThread() async throws {
        let client = ThreadRecordingDaemonClient(request: Self.sampleRequest)
        let presenter = ThreadRecordingPresenter()
        let controller = ApprovalController(
            client: client,
            presenter: presenter,
            logger: NoopApprovalLogger()
        )

        _ = try await controller.run()

        XCTAssertEqual(client.fetchThreadObservation, .background)
        XCTAssertEqual(client.submitThreadObservation, .background)
        XCTAssertTrue(presenter.decideRanOnMainThread)
    }

    deinit {
        /* Required by SwiftLint. */
    }
}

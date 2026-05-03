import Foundation

/// Serial worker that keeps blocking daemon socket I/O off the main actor.
final class ApprovalDaemonClientWorker: @unchecked Sendable {
    private let client: ApprovalDaemonClient
    private let queue: DispatchQueue

    init(
        client: ApprovalDaemonClient,
        queue: DispatchQueue = DispatchQueue(label: "com.kovyrin.agent-secret.approver.daemon-client")
    ) {
        self.client = client
        self.queue = queue
    }

    func fetchPendingRequest() async throws -> ApprovalRequest {
        try await perform {
            try self.client.fetchPendingRequest()
        }
    }

    func submit(_ decision: ApprovalDecision) async throws {
        try await perform {
            try self.client.submit(decision)
        }
    }

    private func perform<Value>(_ operation: @escaping @Sendable () throws -> Value) async throws -> Value {
        try await withCheckedThrowingContinuation { continuation in
            queue.async {
                do {
                    let value = try operation()
                    continuation.resume(returning: value)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    deinit {
        /* Required by SwiftLint. */
    }
}

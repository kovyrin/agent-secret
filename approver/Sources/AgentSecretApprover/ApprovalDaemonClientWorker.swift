import Foundation

/// Serial worker that keeps blocking daemon socket I/O off the main actor.
final class ApprovalDaemonClientWorker: @unchecked Sendable {
    private let clientFactory: () throws -> ApprovalDaemonClient
    private var client: ApprovalDaemonClient?
    private let queue: DispatchQueue

    convenience init(
        client: ApprovalDaemonClient,
        queue: DispatchQueue = DispatchQueue(label: "com.kovyrin.agent-secret.approver.daemon-client")
    ) {
        self.init(clientFactory: { client }, queue: queue)
    }

    init(
        clientFactory: @escaping () throws -> ApprovalDaemonClient,
        queue: DispatchQueue = DispatchQueue(label: "com.kovyrin.agent-secret.approver.daemon-client")
    ) {
        self.clientFactory = clientFactory
        self.queue = queue
    }

    func fetchPendingRequest() async throws -> ApprovalRequest {
        try await perform {
            try self.clientOnQueue().fetchPendingRequest()
        }
    }

    func submit(_ decision: ApprovalDecision) async throws {
        try await perform {
            try self.clientOnQueue().submit(decision)
        }
    }

    private func clientOnQueue() throws -> ApprovalDaemonClient {
        if let client {
            return client
        }
        let client = try clientFactory()
        self.client = client
        return client
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

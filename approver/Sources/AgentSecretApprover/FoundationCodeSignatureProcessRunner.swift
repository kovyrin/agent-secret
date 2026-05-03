import Foundation

#if canImport(Darwin)
    import Darwin

    struct FoundationCodeSignatureProcessRunner: CodeSignatureProcessRunning {
        private final class ProcessOutputBuffer: @unchecked Sendable {
            private let lock = NSLock()
            private var data = Data()

            func append(_ chunk: Data) {
                lock.lock()
                data.append(chunk)
                lock.unlock()
            }

            func text() -> String {
                lock.lock()
                defer { lock.unlock() }
                return String(data: data, encoding: .utf8) ?? ""
            }

            deinit {
                /* Required by SwiftLint. */
            }
        }

        private static let minimumTimeout: TimeInterval = 0.001
        private static let millisecondsPerSecond: TimeInterval = 1e3
        private static let outputDrainTimeout: TimeInterval = 1
        private static let shutdownTimeout: TimeInterval = 0.2

        private static func readOutput(from pipe: Pipe) -> (done: DispatchSemaphore, text: () -> String) {
            let done = DispatchSemaphore(value: 0)
            let output = ProcessOutputBuffer()
            DispatchQueue.global(qos: .utility).async {
                while true {
                    let data = pipe.fileHandleForReading.availableData
                    if data.isEmpty {
                        break
                    }
                    output.append(data)
                }
                done.signal()
            }
            return (
                done,
                {
                    output.text()
                }
            )
        }

        private static func stopTimedOutProcess(_ process: Process, termination: DispatchSemaphore) {
            process.terminate()
            if termination.wait(timeout: deadline(after: shutdownTimeout)) == .timedOut {
                kill(process.processIdentifier, SIGKILL)
                _ = termination.wait(timeout: deadline(after: shutdownTimeout))
            }
        }

        private static func deadline(after seconds: TimeInterval) -> DispatchTime {
            let boundedSeconds = max(seconds, minimumTimeout)
            let milliseconds = max(1, Int((boundedSeconds * millisecondsPerSecond).rounded(.up)))
            return .now() + .milliseconds(milliseconds)
        }

        func run(executableURL: URL, arguments: [String], timeout: TimeInterval) throws -> CodeSignatureProcessResult {
            let process = Process()
            process.executableURL = executableURL
            process.arguments = arguments
            let output = Pipe()
            process.standardOutput = output
            process.standardError = output

            let termination = DispatchSemaphore(value: 0)
            process.terminationHandler = { _ in
                termination.signal()
            }

            do {
                try process.run()
            } catch {
                throw SocketDaemonClientError.untrustedDaemon(
                    "launch daemon process code signature validation failed: \(error)"
                )
            }

            let outputReader = Self.readOutput(from: output)
            guard termination.wait(timeout: Self.deadline(after: timeout)) == .success else {
                Self.stopTimedOutProcess(process, termination: termination)
                _ = outputReader.done.wait(timeout: Self.deadline(after: Self.outputDrainTimeout))
                throw SocketDaemonClientError.untrustedDaemon("daemon process code signature validation timed out")
            }

            _ = outputReader.done.wait(timeout: Self.deadline(after: Self.outputDrainTimeout))
            return CodeSignatureProcessResult(
                output: outputReader.text(),
                terminationStatus: process.terminationStatus
            )
        }
    }
#endif

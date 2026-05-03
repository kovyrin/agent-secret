import Foundation

#if canImport(Darwin)
    protocol CodeSignatureProcessRunning {
        func run(executableURL: URL, arguments: [String], timeout: TimeInterval) throws -> CodeSignatureProcessResult
    }
#endif

import Foundation

#if canImport(Darwin)
    struct CodeSignatureProcessResult {
        let output: String
        let terminationStatus: Int32
    }
#endif

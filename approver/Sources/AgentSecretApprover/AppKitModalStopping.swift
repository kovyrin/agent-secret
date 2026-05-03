import Foundation

#if canImport(AppKit)
    @MainActor
    @objc
    protocol AppKitModalStopping: NSObjectProtocol {
        func stopModal()
    }
#endif

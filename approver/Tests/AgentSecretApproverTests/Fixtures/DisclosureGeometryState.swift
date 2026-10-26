#if canImport(AppKit) && canImport(SwiftUI)
    import SwiftUI

    @MainActor
    final class DisclosureGeometryState: ObservableObject {
        @Published var isExpanded = false
        var contentVisible = false
    }
#endif

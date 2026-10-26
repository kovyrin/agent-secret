#if canImport(SwiftUI)
    import SwiftUI

    /// The entire labeled row is a button, with the same target for pointer and keyboard input.
    struct ApprovalPanelDisclosureStyle: DisclosureGroupStyle {
        func makeBody(configuration: Configuration) -> some View {
            ApprovalPanelDisclosureBody(configuration: configuration)
        }
    }
#endif

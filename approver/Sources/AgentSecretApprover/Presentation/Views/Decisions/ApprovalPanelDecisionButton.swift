#if canImport(SwiftUI)
    import SwiftUI

    struct ApprovalPanelDecisionButton: View {
        private typealias Layout = ApprovalPanelLayout

        let spec: ApprovalPanelDecisionButtonSpec
        let action: () -> Void

        var body: some View {
            Button(action: action) {
                HStack(spacing: Layout.compactSpacing) {
                    Text(spec.title)
                    Text(spec.decision == .deny ? "esc" : "⌘↩")
                        .font(.system(size: Layout.captionFontSize))
                        .foregroundStyle(spec.decision == .deny ? Color.secondary : ApprovalPanelTheme.allowForeground)
                }
                .font(.system(size: Layout.labelFontSize, weight: .semibold))
                .foregroundStyle(spec.decision == .deny ? Color.primary : ApprovalPanelTheme.allowForeground)
                .frame(maxWidth: .infinity, minHeight: Layout.primaryButtonHeight)
                .background(
                    spec.decision == .deny ? ApprovalPanelTheme.raised : ApprovalPanelTheme.allowBackground,
                    in: RoundedRectangle(cornerRadius: Layout.standardSpacing)
                )
                .overlay {
                    RoundedRectangle(cornerRadius: Layout.standardSpacing)
                        .stroke(spec.decision == .deny ? ApprovalPanelTheme.border : .clear)
                }
            }
            .buttonStyle(.plain)
            .keyboardShortcut(spec.keyboardShortcut)
            .background {
                if spec.decision != .deny {
                    // Numeric keypad Enter is U+0003. Return has its own key equivalent.
                    Button(spec.title, action: action)
                        .keyboardShortcut("\u{3}", modifiers: .command)
                        .opacity(0)
                        .allowsHitTesting(false)
                        .accessibilityHidden(true)
                }
            }
            .disabled(!spec.isEnabled)
        }
    }
#endif

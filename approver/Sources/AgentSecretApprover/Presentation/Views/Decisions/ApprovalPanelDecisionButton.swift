#if canImport(SwiftUI)
    import SwiftUI

    struct ApprovalPanelDecisionButton: View {
        private typealias Layout = ApprovalPanelLayout

        let spec: ApprovalPanelDecisionButtonSpec
        let action: () -> Void

        var body: some View {
            let button = Button(action: action) {
                HStack(spacing: Layout.compactSpacing) {
                    Text(spec.title)
                    if spec.decision == .deny {
                        Text("esc").font(.system(size: Layout.captionFontSize)).foregroundStyle(.secondary)
                    }
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
            .disabled(!spec.isEnabled)
            if let shortcut = spec.keyboardShortcut {
                button.keyboardShortcut(shortcut)
            } else {
                button
            }
        }
    }
#endif

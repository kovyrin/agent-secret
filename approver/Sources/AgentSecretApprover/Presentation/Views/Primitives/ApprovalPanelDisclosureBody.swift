#if canImport(SwiftUI)
    import SwiftUI

    struct ApprovalPanelDisclosureBody: View {
        private typealias Layout = ApprovalPanelLayout

        let configuration: DisclosureGroupStyleConfiguration

        @State private var hovering = false
        @Environment(\.colorSchemeContrast)
        private var contrast

        var body: some View {
            VStack(alignment: .leading, spacing: 0) {
                Button {
                    configuration.isExpanded.toggle()
                } label: {
                    HStack(spacing: Layout.compactSpacing) {
                        Image(systemName: configuration.isExpanded ? "chevron.down" : "chevron.right")
                            .font(.system(size: Layout.captionFontSize, weight: .semibold))
                            .foregroundStyle(hovering ? .primary : .secondary)
                            .accessibilityHidden(true)
                        configuration.label.frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .padding(.horizontal, Layout.rowSpacing)
                    .padding(.vertical, Layout.standardSpacing)
                    .contentShape(Rectangle())
                    .background(hovering ? Color.primary.opacity(hoverOpacity) : .clear)
                }
                .buttonStyle(.plain)
                .onHover { hovering = $0 }
                .accessibilityValue(configuration.isExpanded ? "Expanded" : "Collapsed")
                if configuration.isExpanded {
                    configuration.content.padding(Layout.rowSpacing)
                }
            }
        }

        private var hoverOpacity: Double {
            contrast == .increased ? Layout.disclosureHoverContrastOpacity : Layout.disclosureHoverOpacity
        }
    }
#endif

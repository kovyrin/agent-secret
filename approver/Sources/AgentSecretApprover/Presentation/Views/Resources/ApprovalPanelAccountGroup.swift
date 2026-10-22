#if canImport(SwiftUI)
    import SwiftUI

    struct ApprovalPanelAccountGroup: View {
        private typealias Layout = ApprovalPanelLayout

        let group: ResourceAccountGroupViewModel

        var body: some View {
            VStack(alignment: .leading, spacing: 0) {
                VStack(alignment: .leading, spacing: Layout.labelSpacing) {
                    HStack(alignment: .firstTextBaseline, spacing: Layout.compactSpacing) {
                        Label(group.identity.provider, systemImage: "lock.shield")
                            .fontWeight(.semibold)
                        Spacer(minLength: 0)
                        Text("\(group.resources.count)").foregroundStyle(.secondary)
                    }
                    Text(group.identity.label).foregroundStyle(.secondary)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .font(.system(size: Layout.captionFontSize))
                .padding(.horizontal, Layout.rowSpacing)
                .padding(.vertical, Layout.compactSpacing)
                .background(ApprovalPanelTheme.sunken)
                ForEach(Array(group.resources.enumerated()), id: \.offset) { _, resource in
                    Divider()
                    ApprovalPanelExpandableResource(resource: resource)
                }
            }
        }
    }
#endif

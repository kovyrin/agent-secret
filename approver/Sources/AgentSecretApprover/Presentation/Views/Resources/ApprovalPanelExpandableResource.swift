#if canImport(SwiftUI)
    import SwiftUI

    struct ApprovalPanelExpandableResource: View {
        private typealias Layout = ApprovalPanelLayout

        let resource: RequestedResourceRowViewModel
        let resourceAliasLabel: String
        @State private var expanded = false

        var body: some View {
            DisclosureGroup(isExpanded: $expanded) {
                VStack(alignment: .leading, spacing: Layout.detailSpacing) {
                    detail("Reference", resource.ref)
                    if !resource.account.isEmpty { detail("Account", resource.account) }
                    if !resource.source.isEmpty { detail("Source", resource.source) }
                    if !resource.bitwardenTokenAlias.isEmpty { detail("Token alias", resource.bitwardenTokenAlias) }
                    detail(resourceAliasLabel, resource.alias)
                }
                .padding(.top, Layout.compactSpacing)
            } label: {
                HStack(spacing: Layout.compactSpacing) {
                    Image(systemName: resource.symbolName).foregroundStyle(ApprovalPanelTheme.accent)
                        .accessibilityHidden(true)
                    Text(resource.alias).fontWeight(.semibold)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Spacer(minLength: 0)
                    Text(resource.itemName ?? resource.vaultName)
                        .foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                }
                .font(.system(size: Layout.rowSpacing, design: .monospaced))
            }
            .tint(.secondary)
            .accessibilityHint("Expand to inspect the complete reference and source scope")
        }

        private func detail(_ label: String, _ value: String) -> some View {
            VStack(alignment: .leading, spacing: Layout.tightSpacing) {
                Text(label).font(.system(size: Layout.captionFontSize))
                    .foregroundStyle(.secondary)
                Text(value).font(.system(size: Layout.captionFontSize, design: .monospaced))
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
#endif

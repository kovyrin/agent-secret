import Foundation

#if canImport(SwiftUI)
    import SwiftUI

    struct ApprovalPanelResourceList: View {
        private typealias Metric = ApprovalPanelStyle.Metric

        let heading: String
        let resources: [RequestedResourceRowViewModel]

        var body: some View {
            let aliasColumnWidth = ApprovalPanelResourceListLayout.aliasColumnWidth(for: resources.map(\.alias))

            VStack(alignment: .leading, spacing: Metric.resourceListSpacing) {
                Text(heading)
                    .font(.system(size: Metric.sectionLabelFontSize, weight: .semibold))
                    .foregroundStyle(Color.green)
                ForEach(resources, id: \.alias) { resource in
                    ApprovalPanelResourceListRow(resource: resource, aliasColumnWidth: aliasColumnWidth)
                }
            }
            .padding(Metric.resourcePanelPadding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(panelBackground)
            .overlay(panelBorder)
        }

        private var panelBackground: some View {
            RoundedRectangle(cornerRadius: Metric.panelCornerRadius, style: .continuous)
                .fill(Color.green.opacity(Metric.greenPanelOpacity))
        }

        private var panelBorder: some View {
            RoundedRectangle(cornerRadius: Metric.panelCornerRadius, style: .continuous)
                .stroke(Color.green.opacity(Metric.greenBorderOpacity), lineWidth: Metric.borderWidth)
        }
    }
#endif

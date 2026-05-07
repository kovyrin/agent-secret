import Foundation

#if canImport(AppKit) && canImport(SwiftUI)
    import AppKit
    import SwiftUI

    extension ApprovalRequestPanelView {
        private typealias Metric = ApprovalPanelStyle.Metric

        var resourceSection: some View {
            Group {
                if viewModel.resourceCount == Metric.singleResourceCount {
                    singleResourceSection
                } else if viewModel.resourceCount <= Metric.compactResourceLimit {
                    ApprovalPanelResourceList(heading: resourceCardHeading, resources: viewModel.requestedResources)
                } else {
                    ApprovalPanelResourceGroupList(heading: resourceCardHeading, groups: viewModel.vaultGroups)
                }
            }
        }

        var singleResourceSection: some View {
            VStack(alignment: .leading, spacing: Metric.resourceCardSpacing) {
                Text(resourceCardHeading)
                    .font(.system(size: Metric.sectionLabelFontSize, weight: .semibold))
                    .foregroundStyle(Color.green)
                ForEach(viewModel.requestedResources, id: \.alias) { resource in
                    ApprovalPanelResourceCard(resource: resource)
                }
            }
            .padding(Metric.resourcePanelPadding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(resourcePanelBackground)
            .overlay(resourcePanelBorder)
        }

        var resourceCardHeading: String {
            viewModel.requestedResourcesHeading
        }

        var resourcePanelBackground: some View {
            RoundedRectangle(cornerRadius: Metric.panelCornerRadius, style: .continuous)
                .fill(Color.green.opacity(Metric.greenPanelOpacity))
        }

        var resourcePanelBorder: some View {
            RoundedRectangle(cornerRadius: Metric.panelCornerRadius, style: .continuous)
                .stroke(Color.green.opacity(Metric.greenBorderOpacity), lineWidth: Metric.borderWidth)
        }
    }
#endif

import Foundation

#if canImport(AppKit) && canImport(SwiftUI)
    import AppKit
    import SwiftUI

    extension ApprovalRequestPanelView {
        private typealias Metric = ApprovalPanelStyle.Metric

        var secretSection: some View {
            Group {
                if viewModel.secretCount == Metric.singleSecretCount {
                    singleSecretSection
                } else if viewModel.secretCount <= Metric.compactSecretLimit {
                    ApprovalPanelSecretList(heading: secretCardHeading, secrets: viewModel.requestedSecrets)
                } else {
                    ApprovalPanelSecretGroupList(heading: secretCardHeading, groups: viewModel.vaultGroups)
                }
            }
        }

        var singleSecretSection: some View {
            VStack(alignment: .leading, spacing: Metric.secretCardSpacing) {
                Text(secretCardHeading)
                    .font(.system(size: Metric.sectionLabelFontSize, weight: .semibold))
                    .foregroundStyle(Color.green)
                ForEach(viewModel.requestedSecrets, id: \.alias) { secret in
                    ApprovalPanelSecretCard(secret: secret)
                }
            }
            .padding(Metric.secretPanelPadding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(secretPanelBackground)
            .overlay(secretPanelBorder)
        }

        var secretCardHeading: String {
            if viewModel.secretCount == Metric.singleSecretCount {
                return "Requested secret"
            }
            return "Requested secrets"
        }

        var secretPanelBackground: some View {
            RoundedRectangle(cornerRadius: Metric.panelCornerRadius, style: .continuous)
                .fill(Color.green.opacity(Metric.greenPanelOpacity))
        }

        var secretPanelBorder: some View {
            RoundedRectangle(cornerRadius: Metric.panelCornerRadius, style: .continuous)
                .stroke(Color.green.opacity(Metric.greenBorderOpacity), lineWidth: Metric.borderWidth)
        }
    }
#endif

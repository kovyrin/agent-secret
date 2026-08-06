import Foundation

#if canImport(AppKit) && canImport(SwiftUI)
    import AppKit
    import SwiftUI

    extension ApprovalRequestPanelView {
        private typealias Metric = ApprovalPanelStyle.Metric
        private typealias Palette = ApprovalPanelStyle.Palette

        var requestSummary: some View {
            VStack(alignment: .leading, spacing: Metric.sectionSpacing) {
                header
                prompt
                if viewModel.highScopeWarning {
                    ApprovalPanelHighScopeWarning(
                        printsEnvironmentWarning: viewModel.printsEnvironmentWarning,
                        resourceCount: viewModel.resourceCount
                    )
                }
                ApprovalPanelReasonCard(reason: viewModel.reason)
                ApprovalRequestContextSection(viewModel: viewModel)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }

        var cardBackground: some View {
            RoundedRectangle(cornerRadius: Metric.cardCornerRadius, style: .continuous)
                .fill(Color(nsColor: .windowBackgroundColor).opacity(Metric.cardOpacity))
                .shadow(
                    color: .black.opacity(Metric.cardShadowOpacity),
                    radius: Metric.cardShadowRadius,
                    x: Metric.zeroOffset,
                    y: Metric.cardShadowYOffset
                )
        }

        var caution: some View {
            HStack(alignment: .top, spacing: Metric.cautionSpacing) {
                Image(systemName: "exclamationmark.triangle")
                    .font(.system(size: Metric.cautionIconSize, weight: .semibold))
                    .foregroundStyle(Color.orange)
                    .accessibilityHidden(true)
                Text("Caution: ")
                    .fontWeight(.semibold) +
                    Text(viewModel.cautionMessages.joined(separator: "\n"))
            }
            .font(.system(size: Metric.bodyFontSize))
            .foregroundStyle(Palette.cautionText)
            .padding(Metric.cautionPadding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .fixedSize(horizontal: false, vertical: true)
            .background(cautionBackground)
            .overlay(cautionBorder)
        }

        var reusableDetail: String {
            if viewModel.allowsReusableApproval {
                return viewModel.allowReusableTitle.replacingOccurrences(of: "\n", with: " • ")
            }
            return viewModel.scopeSummary.replacingOccurrences(of: "\n", with: " • ")
        }

        var footer: some View {
            HStack(alignment: .top, spacing: Metric.footerSpacing) {
                Image(systemName: "lock")
                    .font(.system(size: Metric.footerIconSize, weight: .medium))
                    .foregroundStyle(.secondary)
                    .accessibilityHidden(true)
                Text(viewModel.footerMessage)
                    .font(.system(size: Metric.bodyFontSize))
                    .foregroundStyle(.secondary)
                    .lineLimit(Metric.twoLineLimit)
                    .multilineTextAlignment(.leading)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .frame(maxWidth: .infinity, alignment: .center)
        }

        private var header: some View {
            HStack(alignment: .center, spacing: Metric.headerSpacing) {
                ApprovalPanelShieldKeyIcon()
                    .frame(width: Metric.headerIconSize, height: Metric.headerIconSize)
                Text(viewModel.title)
                    .font(.system(size: Metric.titleFontSize, weight: .bold, design: .rounded))
                    .foregroundStyle(.primary)
            }
        }

        private var prompt: some View {
            VStack(alignment: .leading, spacing: Metric.promptSpacing) {
                Text(viewModel.promptQuestion)
                    .font(.system(size: Metric.promptFontSize, weight: .semibold, design: .rounded))
                    .foregroundStyle(.secondary)
                if viewModel.operation != .sessionCreate {
                    promptAccessLine
                }
            }
        }

        private var promptAccessLine: some View {
            HStack(spacing: Metric.inlineSpacing) {
                ApprovalPanelPillText(text: viewModel.executable)
                Text(viewModel.accessSummary)
            }
            .font(.system(size: Metric.inlineFontSize))
            .fixedSize(horizontal: false, vertical: true)
        }

        private var cautionBackground: some View {
            RoundedRectangle(cornerRadius: Metric.cautionCornerRadius, style: .continuous)
                .fill(Color.orange.opacity(Metric.cautionPanelOpacity))
        }

        private var cautionBorder: some View {
            RoundedRectangle(cornerRadius: Metric.cautionCornerRadius, style: .continuous)
                .stroke(Color.orange.opacity(Metric.cautionBorderOpacity), lineWidth: Metric.borderWidth)
        }
    }
#endif

import Foundation

#if canImport(AppKit) && canImport(SwiftUI)
    import AppKit
    import SwiftUI

    struct ApprovalRequestPanelView: View {
        private typealias Metric = ApprovalPanelStyle.Metric
        private typealias Palette = ApprovalPanelStyle.Palette

        let viewModel: ApprovalRequestViewModel
        let decide: (ApprovalDecisionKind) -> Void

        @State private var detailsExpanded = false
        @State private var textInspection: ApprovalPanelTextInspection?

        var body: some View {
            VStack(alignment: .leading, spacing: Metric.sectionSpacing) {
                header
                prompt
                if viewModel.highScopeWarning {
                    ApprovalPanelHighScopeWarning(
                        printsEnvironmentWarning: viewModel.printsEnvironmentWarning,
                        secretCount: viewModel.secretCount
                    )
                }
                secretSection
                requestContext
                if viewModel.printsEnvironmentWarning, !viewModel.highScopeWarning {
                    caution
                }
                details
                decisionButtons
                footer
            }
            .padding(.horizontal, Metric.cardHorizontalPadding)
            .padding(.vertical, Metric.cardVerticalPadding)
            .frame(width: Metric.cardWidth)
            .background(cardBackground)
            .padding(Metric.outerPadding)
            .sheet(item: $textInspection) { inspection in
                ApprovalPanelTextInspector(inspection: inspection)
            }
        }

        private var cardBackground: some View {
            RoundedRectangle(cornerRadius: Metric.cardCornerRadius, style: .continuous)
                .fill(Color(nsColor: .windowBackgroundColor).opacity(Metric.cardOpacity))
                .shadow(
                    color: .black.opacity(Metric.cardShadowOpacity),
                    radius: Metric.cardShadowRadius,
                    x: Metric.zeroOffset,
                    y: Metric.cardShadowYOffset
                )
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
                    .font(.system(size: Metric.promptFontSize, weight: .bold, design: .rounded))
                promptAccessLine
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

        private var secretSection: some View {
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

        private var singleSecretSection: some View {
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

        private var secretCardHeading: String {
            if viewModel.secretCount == Metric.singleSecretCount {
                return "Requested secret"
            }
            return "Requested secrets"
        }

        private var secretPanelBackground: some View {
            RoundedRectangle(cornerRadius: Metric.panelCornerRadius, style: .continuous)
                .fill(Color.green.opacity(Metric.greenPanelOpacity))
        }

        private var secretPanelBorder: some View {
            RoundedRectangle(cornerRadius: Metric.panelCornerRadius, style: .continuous)
                .stroke(Color.green.opacity(Metric.greenBorderOpacity), lineWidth: Metric.borderWidth)
        }

        private var requestContext: some View {
            VStack(alignment: .leading, spacing: Metric.contextRowSpacing) {
                ApprovalPanelContextRow(
                    icon: "bubble.left",
                    title: "Reason",
                    value: viewModel.reason,
                    valueLineLimit: nil
                )
                ApprovalPanelContextRow(
                    icon: "terminal",
                    title: "Command",
                    value: viewModel.command,
                    inspectAction: commandInspectionAction
                )
                ApprovalPanelContextRow(icon: "folder", title: "Project folder", value: viewModel.projectFolder)
                ApprovalPanelContextRow(icon: "scope", title: "Scope", value: viewModel.scopeSummary)
            }
        }

        private var commandInspectionAction: (() -> Void)? {
            guard viewModel.commandNeedsInspector else {
                return nil
            }
            return {
                textInspection = ApprovalPanelTextInspection(
                    title: "Full command",
                    text: viewModel.command
                )
            }
        }

        private var caution: some View {
            HStack(alignment: .top, spacing: Metric.cautionSpacing) {
                Image(systemName: "exclamationmark.triangle")
                    .font(.system(size: Metric.cautionIconSize, weight: .semibold))
                    .foregroundStyle(Color.orange)
                    .accessibilityHidden(true)
                Text("Caution: ")
                    .fontWeight(.semibold) +
                    Text("This command can print environment variables.\nOnly approve if you expected this.")
            }
            .font(.system(size: Metric.bodyFontSize))
            .foregroundStyle(Palette.cautionText)
            .padding(Metric.cautionPadding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .fixedSize(horizontal: false, vertical: true)
            .background(cautionBackground)
            .overlay(cautionBorder)
        }

        private var cautionBackground: some View {
            RoundedRectangle(cornerRadius: Metric.cautionCornerRadius, style: .continuous)
                .fill(Color.orange.opacity(Metric.cautionPanelOpacity))
        }

        private var cautionBorder: some View {
            RoundedRectangle(cornerRadius: Metric.cautionCornerRadius, style: .continuous)
                .stroke(Color.orange.opacity(Metric.cautionBorderOpacity), lineWidth: Metric.borderWidth)
        }

        private var details: some View {
            DisclosureGroup(isExpanded: $detailsExpanded) {
                VStack(alignment: .leading, spacing: Metric.detailSpacing) {
                    ApprovalPanelDetailLine(
                        label: "Resolved binary",
                        value: viewModel.resolvedExecutable ?? viewModel.executable
                    )
                    ApprovalPanelDetailLine(label: "Working directory", value: viewModel.cwd)
                    if let overrideWarning: String = viewModel.overrideWarning {
                        ApprovalPanelDetailLine(label: "Overrides", value: overrideWarning)
                    }
                    ApprovalPanelDetailLine(label: "Reusable approval", value: reusableDetail)
                }
                .padding(.top, Metric.detailTopPadding)
                .padding(.leading, Metric.detailLeadingPadding)
            } label: {
                VStack(alignment: .leading, spacing: Metric.detailLabelSpacing) {
                    Text("Details")
                        .font(.system(size: Metric.detailTitleFontSize, weight: .semibold))
                    Text("Resolved binary, working directory, and approval behavior")
                        .font(.system(size: Metric.detailSubtitleFontSize))
                        .foregroundStyle(.secondary)
                }
            }
            .font(.system(size: Metric.bodyFontSize))
            .tint(.primary)
        }

        private var reusableDetail: String {
            viewModel.allowReusableTitle.replacingOccurrences(of: "\n", with: " • ")
        }

        private var decisionButtons: some View {
            HStack(spacing: Metric.buttonSpacing) {
                denyButton
                    .frame(width: Metric.decisionButtonWidth)
                allowOnceButton
                    .frame(width: Metric.decisionButtonWidth)
                allowReusableButton
                    .frame(width: Metric.decisionButtonWidth)
            }
            .frame(height: Metric.buttonHeight)
        }

        private var denyButton: some View {
            ApprovalPanelDecisionButton(
                icon: "shield.slash",
                title: "Deny",
                subtitle: "Default action",
                role: .secondary,
                keyboardShortcut: .cancelAction
            ) {
                decide(.deny)
            }
        }

        private var allowOnceButton: some View {
            ApprovalPanelDecisionButton(
                icon: "clock",
                title: "Allow once",
                subtitle: "This time only",
                role: .secondary,
                keyboardShortcut: .defaultAction
            ) {
                decide(.approveOnce)
            }
        }

        private var allowReusableButton: some View {
            ApprovalPanelDecisionButton(
                icon: "checkmark.shield",
                title: "Allow same command briefly",
                subtitle: "\(viewModel.compactTimeRemaining) or \(viewModel.reusableUses) uses",
                role: .primary,
                keyboardShortcut: nil
            ) {
                decide(.approveReusable)
            }
        }

        private var footer: some View {
            HStack(alignment: .top, spacing: Metric.footerSpacing) {
                Image(systemName: "lock")
                    .font(.system(size: Metric.footerIconSize, weight: .medium))
                    .foregroundStyle(.secondary)
                    .accessibilityHidden(true)
                Text(viewModel.footerMessage)
                    .font(.system(size: Metric.bodyFontSize))
                    .foregroundStyle(.secondary)
                    .lineLimit(Metric.twoLineLimit)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
#endif

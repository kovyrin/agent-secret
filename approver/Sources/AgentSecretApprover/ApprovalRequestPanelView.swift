import Foundation

#if canImport(AppKit) && canImport(SwiftUI)
    import AppKit
    import SwiftUI

    struct ApprovalRequestPanelView: View {
        private typealias Metric = ApprovalPanelStyle.Metric
        private typealias Palette = ApprovalPanelStyle.Palette

        let request: ApprovalRequest
        let decide: (ApprovalDecisionKind) -> Void

        @State private var detailsExpanded = false
        @State private var didDecide = false
        @State private var now: Date
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
            .onAppear {
                handleClockTick(Date())
            }
            .onReceive(
                Timer.publish(every: Metric.countdownTickInterval, on: .main, in: .common)
                    .autoconnect()
            ) { date in
                handleClockTick(date)
            }
        }

        var viewModel: ApprovalRequestViewModel {
            ApprovalRequestViewModel(request: request, now: now)
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
                    title: "Command arguments",
                    text: viewModel.commandInspectionText
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
                ForEach(decisionButtonSpecs, id: \.decision) { spec in
                    ApprovalPanelDecisionButton(spec: spec) {
                        complete(with: expiration.guardDecision(spec.decision, at: Date()))
                    }
                    .frame(width: Metric.decisionButtonWidth)
                }
            }
            .frame(height: Metric.buttonHeight)
        }

        private var decisionButtonSpecs: [ApprovalPanelDecisionButtonSpec] {
            ApprovalPanelDecisionButtonSpec.makeAll(viewModel: viewModel)
        }

        private var expiration: ApprovalPromptExpiration {
            ApprovalPromptExpiration(expiresAt: request.expiresAt)
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

        init(
            request: ApprovalRequest,
            now: Date = Date(),
            decide: @escaping (ApprovalDecisionKind) -> Void
        ) {
            self.request = request
            self.decide = decide
            _now = State(initialValue: now)
        }

        private func handleClockTick(_ date: Date) {
            now = date
            if let timeoutDecision: ApprovalDecisionKind = expiration.timeoutDecision(at: date) {
                complete(with: timeoutDecision)
            }
        }

        private func complete(with decision: ApprovalDecisionKind) {
            guard !didDecide else {
                return
            }
            didDecide = true
            decide(decision)
        }
    }
#endif

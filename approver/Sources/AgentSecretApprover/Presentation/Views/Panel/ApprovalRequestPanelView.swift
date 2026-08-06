import Foundation

#if canImport(AppKit) && canImport(SwiftUI)
    import AppKit
    import SwiftUI

    struct ApprovalRequestPanelView: View {
        private typealias Metric = ApprovalPanelStyle.Metric

        let request: ApprovalRequest
        let maxScrollableContentHeight: CGFloat
        let contentHeightDidChange: ((CGFloat) -> Void)?
        let decide: (ApprovalDecisionKind) -> Void

        @State private var detailsExpanded = false
        @State private var didDecide = false
        @State private var now: Date
        @State private var scrollContentHeight: CGFloat = 0

        var body: some View {
            VStack(alignment: .leading, spacing: Metric.sectionSpacing) {
                scrollableRequestSection
                pinnedDecisionSection
            }
            .padding(.horizontal, Metric.cardHorizontalPadding)
            .padding(.vertical, Metric.cardVerticalPadding)
            .frame(width: Metric.cardWidth)
            .background(cardBackground)
            .padding(Metric.outerPadding)
            .onPreferenceChange(ApprovalPanelMeasurements.Key.self, perform: handleMeasurements)
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

        private var scrollableRequestSection: some View {
            ScrollView(.vertical) {
                VStack(alignment: .leading, spacing: Metric.sectionSpacing) {
                    requestSummary
                    resourceSection
                    if !viewModel.cautionMessages.isEmpty {
                        caution
                    }
                    details
                }
                .background {
                    GeometryReader { proxy in
                        Color.clear.preference(
                            key: ApprovalPanelMeasurements.Key.self,
                            value: ApprovalPanelMeasurements.Value(scrollContentHeight: proxy.size.height)
                        )
                    }
                }
            }
            .frame(height: scrollViewportHeight)
            .scrollIndicators(.automatic)
        }

        private var pinnedDecisionSection: some View {
            VStack(alignment: .leading, spacing: Metric.sectionSpacing) {
                decisionButtons
                footer
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .background {
                GeometryReader { proxy in
                    Color.clear.preference(
                        key: ApprovalPanelMeasurements.Key.self,
                        value: ApprovalPanelMeasurements.Value(pinnedContentHeight: proxy.size.height)
                    )
                }
            }
        }

        private var scrollViewportHeight: CGFloat? {
            guard scrollContentHeight > Metric.zeroOffset else {
                return nil
            }
            return min(scrollContentHeight, maxScrollableContentHeight)
        }

        var viewModel: ApprovalRequestViewModel {
            ApprovalRequestViewModel(request: request, now: now)
        }

        private var details: some View {
            DisclosureGroup(isExpanded: $detailsExpanded) {
                VStack(alignment: .leading, spacing: Metric.detailSpacing) {
                    ApprovalPanelDetailLine(
                        label: "Command arguments",
                        value: viewModel.commandInspectionText
                    )
                    ApprovalPanelDetailLine(
                        label: "Resolved binary",
                        value: viewModel.resolvedExecutable
                    )
                    ApprovalPanelDetailLine(label: "Working directory", value: viewModel.cwd)
                    ApprovalPanelDetailLine(label: "Scope", value: reusableDetail)
                    ApprovalPanelDetailLine(label: "Request timeout", value: viewModel.timeRemaining)
                    if let sessionBinding = viewModel.sessionBindingInspectionText {
                        ApprovalPanelDetailLine(label: "Session binding", value: sessionBinding)
                    }
                    if let overrideWarning: String = viewModel.overrideWarning {
                        ApprovalPanelDetailLine(label: "Overrides", value: overrideWarning)
                    }
                }
                .padding(.top, Metric.detailTopPadding)
                .padding(.leading, Metric.detailLeadingPadding)
            } label: {
                VStack(alignment: .leading, spacing: Metric.detailLabelSpacing) {
                    Text("Show request details")
                        .font(.system(size: Metric.detailTitleFontSize, weight: .semibold))
                    Text("Complete command, paths, scope, and security metadata")
                        .font(.system(size: Metric.detailSubtitleFontSize))
                        .foregroundStyle(.secondary)
                }
            }
            .font(.system(size: Metric.bodyFontSize))
            .tint(.primary)
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
            .frame(
                maxWidth: .infinity,
                minHeight: Metric.buttonHeight,
                maxHeight: Metric.buttonHeight,
                alignment: .center
            )
        }

        private var decisionButtonSpecs: [ApprovalPanelDecisionButtonSpec] {
            ApprovalPanelDecisionButtonSpec.makeAll(viewModel: viewModel)
        }

        private var expiration: ApprovalPromptExpiration {
            ApprovalPromptExpiration(expiresAt: request.expiresAt)
        }

        init(
            request: ApprovalRequest,
            now: Date = Date(),
            maxScrollableContentHeight: CGFloat = Metric.scrollableApprovalContentMaxHeight,
            contentHeightDidChange: ((CGFloat) -> Void)? = nil,
            decide: @escaping (ApprovalDecisionKind) -> Void
        ) {
            self.request = request
            self.maxScrollableContentHeight = maxScrollableContentHeight
            self.contentHeightDidChange = contentHeightDidChange
            self.decide = decide
            _now = State(initialValue: now)
        }

        private func handleMeasurements(_ measurements: ApprovalPanelMeasurements.Value) {
            let hasCompleteMeasurement = measurements.scrollContentHeight > Metric.zeroOffset &&
                measurements.pinnedContentHeight > Metric.zeroOffset
            guard hasCompleteMeasurement else {
                return
            }
            scrollContentHeight = measurements.scrollContentHeight
            contentHeightDidChange?(
                AppKitApprovalPresenter.idealPanelHeight(
                    scrollContentHeight: min(measurements.scrollContentHeight, maxScrollableContentHeight),
                    pinnedContentHeight: measurements.pinnedContentHeight
                )
            )
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

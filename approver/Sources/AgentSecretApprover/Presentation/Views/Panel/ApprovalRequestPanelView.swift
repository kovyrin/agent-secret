import Foundation

#if canImport(AppKit) && canImport(SwiftUI)
    import AppKit
    import SwiftUI

    struct ApprovalRequestPanelView: View {
        private typealias Layout = ApprovalPanelLayout

        let request: ApprovalRequest
        let size: CGSize
        let measuring: Bool
        let decide: (ApprovalDecisionKind) -> Void

        @State private var interaction = ApprovalPanelInteraction()
        @State private var detailsExpanded = false
        @State private var showsInspector = false
        @State private var now: Date

        var panelDate: Date {
            now
        }

        var scope: ApprovalScope {
            interaction.scope
        }

        var scopeBinding: Binding<ApprovalScope> {
            Binding(get: { interaction.scope }, set: { interaction.select($0) })
        }

        var detailsBinding: Binding<Bool> {
            $detailsExpanded
        }

        var inspectorBinding: Binding<Bool> {
            $showsInspector
        }

        var viewModel: ApprovalRequestViewModel {
            ApprovalRequestViewModel(request: request, now: now)
        }

        var countdown: ApprovalCountdown {
            ApprovalCountdown(request: request, now: now)
        }

        var consequences: ApprovalConsequences {
            ApprovalConsequences(request: request, scope: scope)
        }

        var cardWidth: CGFloat {
            size.width - Layout.outerPadding * Layout.tightSpacing
        }

        var isWide: Bool {
            cardWidth >= Layout.twoColumnMinimumWidth
        }

        var body: some View {
            VStack(spacing: 0) {
                header
                ApprovalPanelCountdownView(countdown: countdown).progress
                Divider()
                if measuring {
                    naturalContent
                } else if isWide {
                    columns
                } else {
                    stacked
                }
            }
            .frame(width: cardWidth, height: measuring ? nil : size.height - Layout.outerPadding * Layout.tightSpacing)
            .disclosureGroupStyle(ApprovalPanelDisclosureStyle())
            .background(ApprovalPanelTheme.surface)
            .clipShape(RoundedRectangle(cornerRadius: Layout.cornerRadius))
            .overlay {
                RoundedRectangle(cornerRadius: Layout.cornerRadius)
                    .stroke(ApprovalPanelTheme.border, lineWidth: 1)
            }
            .padding(Layout.outerPadding)
            .onAppear { handleClockTick(Date()) }
            .onReceive(Timer.publish(every: 1, on: .main, in: .common).autoconnect()) { handleClockTick($0) }
            .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
                handleClockTick(Date())
            }
            .onReceive(NSWorkspace.shared.notificationCenter.publisher(for: NSWorkspace.didWakeNotification)) { _ in
                handleClockTick(Date())
            }
            .onChange(of: countdown.phase) { previous, current in
                guard previous != current, !measuring else {
                    return
                }
                NSAccessibility.post(
                    element: NSApplication.shared,
                    notification: .announcementRequested,
                    userInfo: [
                        .announcement: countdown.announcement,
                        .priority: NSAccessibilityPriorityLevel.medium.rawValue
                    ]
                )
            }
            .id(request.requestID)
            .id(request.nonce)
        }

        private var columns: some View {
            HStack(alignment: .top, spacing: 0) {
                ScrollView { requestSummary.padding(Layout.contextPadding) }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                Divider()
                VStack(spacing: 0) {
                    ScrollView { consequenceContent.padding(Layout.sidebarPadding) }
                    decisionSection.padding(Layout.sidebarPadding)
                }
                .frame(width: Layout.sidebarWidth)
                .background(ApprovalPanelTheme.sunken)
            }
        }

        private var stacked: some View {
            VStack(spacing: 0) {
                ScrollView {
                    VStack(alignment: .leading, spacing: Layout.sectionSpacing) {
                        requestSummary
                        Divider()
                        consequenceContent
                    }
                    .padding(Layout.contextPadding)
                }
                Divider()
                decisionSection.padding(Layout.sidebarPadding)
                    .background(ApprovalPanelTheme.sunken)
            }
        }

        @ViewBuilder private var naturalContent: some View {
            if isWide {
                HStack(alignment: .top, spacing: 0) {
                    requestSummary.padding(Layout.contextPadding).frame(maxWidth: .infinity)
                    VStack(alignment: .leading, spacing: Layout.sectionSpacing) {
                        consequenceContent
                        decisionSection
                    }
                    .padding(Layout.sidebarPadding)
                    .frame(width: Layout.sidebarWidth)
                }
            } else {
                VStack(alignment: .leading, spacing: Layout.sectionSpacing) {
                    requestSummary
                    consequenceContent
                    decisionSection
                }
                .padding(Layout.contextPadding)
            }
        }

        init(
            request: ApprovalRequest,
            now: Date = Date(),
            size: CGSize = Layout.preferredSize,
            measuring: Bool = false,
            decide: @escaping (ApprovalDecisionKind) -> Void
        ) {
            self.request = request
            self.size = size
            self.measuring = measuring
            self.decide = decide
            _now = State(initialValue: now)
        }

        func showInspector() {
            showsInspector = true
        }

        func submit(_ decision: ApprovalDecisionKind) {
            complete(decision, at: Date())
        }

        private func handleClockTick(_ date: Date) {
            guard !measuring else {
                return
            }
            now = date
            if let decision = ApprovalPromptExpiration(expiresAt: request.expiresAt).timeoutDecision(at: date) {
                complete(decision, at: date)
            }
        }

        private func complete(_ decision: ApprovalDecisionKind, at date: Date) {
            if let result = interaction.complete(decision, request: request, at: date) {
                decide(result)
            }
        }
    }
#endif

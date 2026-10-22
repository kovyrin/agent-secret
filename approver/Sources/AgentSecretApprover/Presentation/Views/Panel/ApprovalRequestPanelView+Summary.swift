import Foundation

#if canImport(AppKit) && canImport(SwiftUI)
    import AppKit
    import SwiftUI

    extension ApprovalRequestPanelView {
        private typealias Layout = ApprovalPanelLayout

        var header: some View {
            HStack(spacing: Layout.standardSpacing) {
                Image(systemName: "checkmark.shield").foregroundStyle(ApprovalPanelTheme.accent)
                Text("Agent Secret").foregroundStyle(.secondary)
                Text("/").foregroundStyle(.tertiary)
                Label(operationLabel, systemImage: operationIcon)
                Spacer(minLength: 0)
                Label("Answer within", systemImage: "timer")
                    .foregroundStyle(.secondary)
                Text(countdown.clock).monospacedDigit().frame(minWidth: Layout.clockWidth, alignment: .trailing)
            }
            .font(.system(size: Layout.rowSpacing, weight: .semibold))
            .padding(.horizontal, Layout.sidebarPadding)
            .padding(.vertical, Layout.labelFontSize)
        }

        var requestSummary: some View {
            VStack(alignment: .leading, spacing: Layout.sectionSpacing) {
                if viewModel.highScopeWarning {
                    warning("Broad access: \(viewModel.resourceCount) secrets requested. Review the full scope below.")
                }
                ForEach(Array(viewModel.cautionMessages.enumerated()), id: \.offset) { _, message in
                    warning(message)
                }
                Text(headline)
                    .font(.system(size: Layout.titleFontSize, weight: .semibold))
                    .fixedSize(horizontal: false, vertical: true)
                ApprovalPanelReasonCard(reason: viewModel.reason)
                resourceSection
                contextFacts
                requestDetails
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }

        private var operationLabel: String {
            switch request.operation {
            case .exec:
                "Command request"

            case .itemDescribe:
                "Metadata request"

            case .sessionCreate:
                "Session request"
            }
        }

        private var operationIcon: String {
            request.operation == .itemDescribe ? "doc.text.magnifyingglass" : "terminal"
        }

        private var headline: String {
            if request.operation == .itemDescribe {
                return "Inspect item metadata"
            }
            let subject = request.operation == .sessionCreate ? viewModel.sessionBindingSummary ?? "This session"
                : viewModel.executable
            let resource = viewModel.resourceCount == 1 ? viewModel.requestedResources.first?.alias ?? "one secret"
                : "\(viewModel.resourceCount) secrets"
            return "\(subject) wants \(resource)"
        }

        private var contextFacts: some View {
            VStack(alignment: .leading, spacing: Layout.standardSpacing) {
                fact("Command", viewModel.command)
                fact("Folder", viewModel.projectFolder)
                fact("Binary", viewModel.resolvedExecutable)
                if let binding = viewModel.sessionBindingSummary { fact("Bound to", binding) }
            }
        }

        private var requestDetails: some View {
            DisclosureGroup("Request details", isExpanded: detailsBinding) {
                VStack(alignment: .leading, spacing: Layout.standardSpacing) {
                    fact("Exact argv", viewModel.commandInspectionText)
                    fact("Folder", viewModel.cwd)
                    fact("Deadline", request.expiresAt.formatted(.iso8601))
                    if let binding = viewModel.sessionBindingInspectionText { fact("Binding", binding) }
                    Button("Inspect full request") {
                        showInspector()
                    }
                    .popover(isPresented: inspectorBinding) {
                        ApprovalPanelTextInspector(inspection: ApprovalPanelTextInspection(
                            title: "Complete request", text: viewModel.requestInspectionText
                        ))
                    }
                }
                .padding(.top, Layout.standardSpacing)
            }
            .font(.system(size: Layout.rowSpacing))
        }

        private func fact(_ label: String, _ value: String) -> some View {
            HStack(alignment: .top, spacing: Layout.labelFontSize) {
                Text(label).foregroundStyle(.secondary).frame(width: Layout.factLabelWidth, alignment: .leading)
                Text(value).font(.system(size: Layout.rowSpacing, design: .monospaced))
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .font(.system(size: Layout.rowSpacing))
        }

        private func warning(_ message: String) -> some View {
            Label(message, systemImage: "exclamationmark.triangle")
                .font(.system(size: Layout.rowSpacing))
                .fixedSize(horizontal: false, vertical: true)
                .padding(Layout.standardSpacing)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(
                    Color.orange.opacity(Layout.warningFillOpacity),
                    in: RoundedRectangle(cornerRadius: Layout.warningCornerRadius)
                )
                .overlay(
                    RoundedRectangle(cornerRadius: Layout.warningCornerRadius)
                        .stroke(Color.orange.opacity(Layout.warningBorderOpacity))
                )
        }
    }
#endif

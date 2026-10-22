#if canImport(SwiftUI)
    import SwiftUI

    extension ApprovalRequestPanelView {
        private typealias Layout = ApprovalPanelLayout

        var consequenceContent: some View {
            VStack(alignment: .leading, spacing: Layout.headingFontSize) {
                Text("If you allow").font(.system(size: Layout.labelFontSize, weight: .semibold))
                if ApprovalScope.allowsReuse(request) {
                    Picker("Approval scope", selection: scopeBinding) {
                        Text("This run").tag(ApprovalScope.once)
                        Text("Reuse").tag(ApprovalScope.reusable)
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                    .accessibilityLabel("Approval scope")
                }
                if request.operation == .sessionCreate {
                    VStack(spacing: Layout.compactSpacing) {
                        statistic("Approve within", countdown.clock)
                        statistic("Access after approval", consequences.accessDuration ?? "Duration unavailable")
                        statistic("Read limit", consequences.readLimit ?? "Read limit unavailable")
                    }
                }
                Text(consequences.heading).font(.system(size: Layout.bodyFontSize, weight: .semibold))
                timeline
                Text(consequences.limit)
                    .font(.system(size: Layout.rowSpacing, weight: .semibold))
                    .fixedSize(horizontal: false, vertical: true)
                Text(consequences.retention)
                    .font(.system(size: Layout.rowSpacing))
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }

        var decisionSection: some View {
            VStack(spacing: Layout.compactSpacing) {
                Button { submit(scope.decision(for: request)) } label: {
                    Text(scope.primaryTitle(for: request))
                        .font(.system(size: Layout.labelFontSize, weight: .semibold))
                        .frame(maxWidth: .infinity, minHeight: Layout.primaryButtonHeight)
                }
                .buttonStyle(.plain)
                .foregroundStyle(.white)
                .background(Color(nsColor: .systemGreen), in: RoundedRectangle(cornerRadius: Layout.standardSpacing))
                .disabled(viewModel.isExpired)
                .accessibilityHint(consequences.limit)
                Button { submit(.deny) } label: {
                    HStack(spacing: Layout.compactSpacing) {
                        Text("Deny")
                        Text("esc").font(.system(size: Layout.captionFontSize))
                            .foregroundStyle(.secondary)
                    }
                    .font(.system(size: Layout.labelFontSize, weight: .semibold))
                    .frame(maxWidth: .infinity, minHeight: Layout.clockWidth)
                    .background(ApprovalPanelTheme.raised, in: RoundedRectangle(cornerRadius: Layout.standardSpacing))
                    .overlay(RoundedRectangle(cornerRadius: Layout.standardSpacing).stroke(ApprovalPanelTheme.border))
                }
                .buttonStyle(.plain)
                .keyboardShortcut(.cancelAction)
                deliveryNote
            }
        }

        private var deliveryNote: some View {
            Label(
                "Agent Secret doesn't write secret values to disk. " +
                    "Approved processes can use them as environment variables.",
                systemImage: "lock"
            )
            .font(.system(size: Layout.captionFontSize))
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
        }

        private var timeline: some View {
            VStack(alignment: .leading, spacing: 0) {
                ForEach(Array(consequences.steps.enumerated()), id: \.offset) { index, step in
                    HStack(alignment: .top, spacing: Layout.rowSpacing) {
                        VStack(spacing: Layout.smallSpacing) {
                            Circle()
                                .fill(index == 0 ? ApprovalPanelTheme.accent : .secondary.opacity(Layout.mutedOpacity))
                                .frame(width: Layout.compactSpacing, height: Layout.compactSpacing)
                            Rectangle().fill(ApprovalPanelTheme.border).frame(width: 1)
                        }
                        .padding(.top, Layout.smallSpacing)
                        .accessibilityHidden(true)
                        Text(step).font(.system(size: Layout.bodyFontSize))
                            .fixedSize(horizontal: false, vertical: true)
                            .padding(.bottom, Layout.headingFontSize)
                    }
                }
            }
        }

        private func statistic(_ label: String, _ value: String) -> some View {
            HStack {
                Text(label).foregroundStyle(.secondary)
                Spacer(minLength: Layout.compactSpacing)
                Text(value).fontWeight(.semibold).monospacedDigit()
            }
            .font(.system(size: Layout.captionFontSize))
            .padding(Layout.compactSpacing)
            .background(ApprovalPanelTheme.raised, in: RoundedRectangle(cornerRadius: Layout.compactSpacing))
        }
    }
#endif

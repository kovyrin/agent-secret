import Foundation

#if canImport(SwiftUI)
    import SwiftUI

    public struct GCPOAuthLoginPromptView: View {
        private enum Metric {
            static let boundaryColumnWidth: CGFloat = 258
            static let boundaryPadding: CGFloat = 14
            static let boundarySectionSpacing: CGFloat = 10
            static let consentIconFontSize: CGFloat = 14
            static let consentIconSize: CGFloat = 22
            static let consentRowSpacing: CGFloat = 10
            static let finePrintSpacing: CGFloat = 5
            static let footerSpacing: CGFloat = 12
            static let footerVerticalPadding: CGFloat = 14
            static let headerIconFontSize: CGFloat = 20
            static let headerIconOpacity: Double = 0.12
            static let headerSpacing: CGFloat = 12
            static let iconSize: CGFloat = 38
            static let itemDetailSpacing: CGFloat = 3
            static let itemSpacing: CGFloat = 12
            static let mainContentSpacing: CGFloat = 20
            static let minContentHeight: CGFloat = 460
            static let minContentWidth: CGFloat = 720
            static let panelCornerRadius: CGFloat = 8
            static let panelPadding: CGFloat = 24
            static let primaryButtonMinWidth: CGFloat = 154
            static let sectionSpacing: CGFloat = 16
            static let titleFontSize: CGFloat = 23
        }

        private let prompt: GCPOAuthLoginPrompt
        private let openGoogle: () -> Bool
        private let cancel: () -> Void

        @State private var openCount = 0
        @State private var openFailed = false

        public var body: some View {
            VStack(spacing: 0) {
                VStack(alignment: .leading, spacing: Metric.sectionSpacing) {
                    header
                    Divider()
                    mainContent
                }
                .padding(Metric.panelPadding)

                Spacer(minLength: 0)
                footer
            }
            .frame(
                minWidth: Metric.minContentWidth,
                maxWidth: .infinity,
                minHeight: Metric.minContentHeight,
                maxHeight: .infinity,
                alignment: .topLeading
            )
            .background(Color(nsColor: .windowBackgroundColor))
        }

        private var header: some View {
            HStack(alignment: .center, spacing: Metric.headerSpacing) {
                Image(systemName: "lock.shield")
                    .font(.system(size: Metric.headerIconFontSize, weight: .semibold))
                    .foregroundStyle(.blue)
                    .frame(width: Metric.iconSize, height: Metric.iconSize)
                    .background(Color.blue.opacity(Metric.headerIconOpacity))
                    .clipShape(RoundedRectangle(cornerRadius: Metric.panelCornerRadius))
                    .accessibilityHidden(true)

                VStack(alignment: .leading, spacing: Metric.finePrintSpacing) {
                    Text("Review Google Cloud Login")
                        .font(.system(size: Metric.titleFontSize, weight: .semibold))
                        .foregroundStyle(.primary)
                    Text("Agent Secret will open Google OAuth for \(prompt.accountLabel).")
                        .font(.body)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }

        private var mainContent: some View {
            HStack(alignment: .top, spacing: Metric.mainContentSpacing) {
                consentSection
                    .frame(maxWidth: .infinity, alignment: .topLeading)
                boundarySection
                    .frame(width: Metric.boundaryColumnWidth, alignment: .topLeading)
            }
        }

        private var consentSection: some View {
            VStack(alignment: .leading, spacing: Metric.itemSpacing) {
                Text("Google consent screen")
                    .font(.headline)
                    .foregroundStyle(.primary)

                ForEach(GCPOAuthLoginPromptCopy.consentItems(for: prompt.scopes)) { item in
                    consentRow(item)
                }
            }
        }

        private var boundarySection: some View {
            VStack(alignment: .leading, spacing: Metric.boundarySectionSpacing) {
                Label("Permission boundary", systemImage: "checkmark.shield")
                    .font(.headline)
                    .foregroundStyle(.primary)

                boundaryText(GCPOAuthLoginPromptCopy.meaningText)

                Divider()

                Label("Use a narrow account", systemImage: "exclamationmark.triangle")
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(.primary)
                boundaryText(GCPOAuthLoginPromptCopy.adminRiskText)

                Divider()

                Label("Wrong Chrome profile?", systemImage: "arrow.clockwise")
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(.primary)
                boundaryText(GCPOAuthLoginPromptCopy.retryText)
            }
            .padding(Metric.boundaryPadding)
            .background(Color(nsColor: .controlBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: Metric.panelCornerRadius))
        }

        private var footer: some View {
            HStack(spacing: Metric.footerSpacing) {
                statusText
                Spacer()

                Button("Cancel") {
                    cancel()
                }
                .keyboardShortcut(.cancelAction)
                .controlSize(.large)

                Button {
                    if openGoogle() {
                        openCount += 1
                        openFailed = false
                    } else {
                        openFailed = true
                    }
                } label: {
                    Text(openCount == 0 ? "Open Google" : "Open Google Again")
                        .font(.body.weight(.semibold))
                        .frame(minWidth: Metric.primaryButtonMinWidth)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .keyboardShortcut(.defaultAction)
            }
            .padding(.horizontal, Metric.panelPadding)
            .padding(.vertical, Metric.footerVerticalPadding)
            .background(Color(nsColor: .windowBackgroundColor))
            .overlay(alignment: .top) {
                Divider()
            }
        }

        private var statusText: some View {
            Group {
                if openFailed {
                    Label(
                        "Could not open Google. Check your default browser and try again.",
                        systemImage: "exclamationmark.triangle.fill"
                    )
                    .font(.callout.weight(.semibold))
                    .foregroundStyle(.red)
                } else if openCount > 0 {
                    Label(
                        "Google opened. Switch Chrome profiles, then open again if needed.",
                        systemImage: "arrow.clockwise"
                    )
                    .font(.callout)
                    .foregroundStyle(.secondary)
                } else {
                    Text("Nothing is sent to Google until you continue.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
            }
        }

        public init(
            prompt: GCPOAuthLoginPrompt,
            openGoogle: @escaping () -> Bool,
            cancel: @escaping () -> Void
        ) {
            self.prompt = prompt
            self.openGoogle = openGoogle
            self.cancel = cancel
        }

        private func consentRow(_ item: GCPOAuthConsentItem) -> some View {
            HStack(alignment: .top, spacing: Metric.consentRowSpacing) {
                Image(systemName: consentIconName(for: item.id))
                    .font(.system(size: Metric.consentIconFontSize, weight: .semibold))
                    .foregroundStyle(.blue)
                    .frame(width: Metric.consentIconSize, height: Metric.consentIconSize)
                    .accessibilityHidden(true)

                VStack(alignment: .leading, spacing: Metric.itemDetailSpacing) {
                    Text(item.title)
                        .font(.body.weight(.semibold))
                        .foregroundStyle(.primary)
                    Text(item.detail)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }

        private func boundaryText(_ text: String) -> some View {
            Text(text)
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }

        private func consentIconName(for id: String) -> String {
            switch id {
            case "iam":
                "key.horizontal"

            case "userinfo.email":
                "envelope"

            case "openid":
                "person.crop.circle"

            default:
                "checkmark.circle"
            }
        }
    }
#endif

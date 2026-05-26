import Foundation

#if canImport(SwiftUI)
    import SwiftUI

    public struct GCPOAuthLoginPromptView: View {
        private enum Metric {
            static let bodySpacing: CGFloat = 14
            static let boxPadding: CGFloat = 12
            static let boxSpacing: CGFloat = 7
            static let borderWidth: CGFloat = 1
            static let cardBorderOpacity: Double = 0.08
            static let cardCornerRadius: CGFloat = 20
            static let cardHeight: CGFloat = 360
            static let cardOpacity: Double = 0.98
            static let cardShadowOpacity: Double = 0.22
            static let cardShadowRadius: CGFloat = 18
            static let cardShadowYOffset: CGFloat = 10
            static let cardWidth: CGFloat = 520
            static let footerTopPadding: CGFloat = 12
            static let footerSpacing: CGFloat = 10
            static let footerVerticalPadding: CGFloat = 14
            static let headerIconFontSize: CGFloat = 18
            static let headerIconOpacity: Double = 0.12
            static let headerSpacing: CGFloat = 12
            static let headerTextSpacing: CGFloat = 4
            static let iconSize: CGFloat = 36
            static let itemIconFontSize: CGFloat = 12
            static let itemIconSize: CGFloat = 18
            static let itemRowSpacing: CGFloat = 8
            static let itemTextSpacing: CGFloat = 1
            static let itemTitleLineLimit: Int = 2
            static let itemDetailLineLimit: Int = 2
            static let outerPadding: CGFloat = 14
            static let panelCornerRadius: CGFloat = 8
            static let panelPadding: CGFloat = 22
            static let primaryButtonMinWidth: CGFloat = 124
            static let scopeColumnSpacing: CGFloat = 16
            static let scopeItemSpacing: CGFloat = 5
            static let titleFontSize: CGFloat = 22
        }

        private let prompt: GCPOAuthLoginPrompt
        private let openGoogle: () -> Bool
        private let cancel: () -> Void

        @State private var openCount = 0
        @State private var openFailed = false

        public var body: some View {
            VStack(spacing: 0) {
                VStack(alignment: .leading, spacing: Metric.bodySpacing) {
                    header
                    scopeSummary
                    boundaryBox
                }
                .padding(Metric.panelPadding)

                Spacer(minLength: 0)
                footer
            }
            .frame(width: Metric.cardWidth, height: Metric.cardHeight, alignment: .topLeading)
            .background(Color(nsColor: .windowBackgroundColor).opacity(Metric.cardOpacity))
            .clipShape(cardShape)
            .overlay(cardBorder)
            .shadow(
                color: .black.opacity(Metric.cardShadowOpacity),
                radius: Metric.cardShadowRadius,
                x: 0,
                y: Metric.cardShadowYOffset
            )
            .padding(Metric.outerPadding)
        }

        private var cardShape: RoundedRectangle {
            RoundedRectangle(cornerRadius: Metric.cardCornerRadius, style: .continuous)
        }

        private var cardBorder: some View {
            cardShape.stroke(Color.black.opacity(Metric.cardBorderOpacity), lineWidth: Metric.borderWidth)
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

                VStack(alignment: .leading, spacing: Metric.headerTextSpacing) {
                    Text("Connect Google Cloud")
                        .font(.system(size: Metric.titleFontSize, weight: .semibold))
                        .foregroundStyle(.primary)
                    Text("Agent Secret will open Google OAuth for \(prompt.accountLabel).")
                        .font(.body)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }

        private var scopeSummary: some View {
            VStack(alignment: .leading, spacing: Metric.scopeItemSpacing) {
                Text("Google will ask for:")
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(.primary)

                HStack(alignment: .top, spacing: Metric.scopeColumnSpacing) {
                    ForEach(GCPOAuthLoginPromptCopy.consentItems(for: prompt.scopes)) { item in
                        scopeRow(item)
                            .frame(maxWidth: .infinity, alignment: .topLeading)
                    }
                }
            }
        }

        private var boundaryBox: some View {
            VStack(alignment: .leading, spacing: Metric.boxSpacing) {
                Label("Permission boundary", systemImage: "checkmark.shield")
                    .font(.subheadline.weight(.semibold))

                Text(GCPOAuthLoginPromptCopy.meaningText)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                Text(GCPOAuthLoginPromptCopy.adminRiskText)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(Metric.boxPadding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(nsColor: .controlBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: Metric.panelCornerRadius))
        }

        private var footer: some View {
            HStack(spacing: Metric.footerSpacing) {
                Spacer()
                if openFailed || openCount > 0 {
                    statusText
                }
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
            .padding(.top, Metric.footerTopPadding)
            .padding(.bottom, Metric.footerVerticalPadding)
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
                        "Wrong Chrome profile? Switch profiles and open again.",
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

        private func scopeRow(_ item: GCPOAuthConsentItem) -> some View {
            HStack(alignment: .top, spacing: Metric.itemRowSpacing) {
                Image(systemName: consentIconName(for: item.id))
                    .font(.system(size: Metric.itemIconFontSize, weight: .semibold))
                    .foregroundStyle(.blue)
                    .frame(width: Metric.itemIconSize, height: Metric.itemIconSize)
                    .accessibilityHidden(true)

                VStack(alignment: .leading, spacing: Metric.itemTextSpacing) {
                    Text(item.title)
                        .font(.callout.weight(.semibold))
                        .foregroundStyle(.primary)
                        .lineLimit(Metric.itemTitleLineLimit)
                    Text(item.detail)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(Metric.itemDetailLineLimit)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
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

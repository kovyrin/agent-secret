import Foundation

#if canImport(SwiftUI)
    import SwiftUI

    public struct GCPOAuthLoginPromptView: View {
        private enum Metric {
            static let buttonCornerRadius: CGFloat = 8
            static let buttonHorizontalPadding: CGFloat = 18
            static let buttonVerticalPadding: CGFloat = 11
            static let contentSpacing: CGFloat = 18
            static let finePrintSpacing: CGFloat = 8
            static let footerSpacing: CGFloat = 12
            static let iconColumnWidth: CGFloat = 18
            static let itemDetailSpacing: CGFloat = 3
            static let itemSpacing: CGFloat = 10
            static let panelPadding: CGFloat = 30
            static let sectionSpacing: CGFloat = 12
            static let titleFontSize: CGFloat = 24
        }

        private let prompt: GCPOAuthLoginPrompt
        private let openGoogle: () -> Bool
        private let cancel: () -> Void

        @State private var openCount = 0
        @State private var openFailed = false

        public var body: some View {
            VStack(alignment: .leading, spacing: Metric.contentSpacing) {
                header
                consentItems
                meaning
                footer
            }
            .padding(Metric.panelPadding)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            .background(Color(nsColor: .windowBackgroundColor))
        }

        private var header: some View {
            VStack(alignment: .leading, spacing: Metric.finePrintSpacing) {
                Text("Connect Agent Secret to Google Cloud")
                    .font(.system(size: Metric.titleFontSize, weight: .semibold))
                    .foregroundStyle(.primary)
                Text("Agent Secret will open Google OAuth for \(prompt.accountLabel). Google will ask you to approve:")
                    .font(.body)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }

        private var consentItems: some View {
            VStack(alignment: .leading, spacing: Metric.itemSpacing) {
                ForEach(GCPOAuthLoginPromptCopy.consentItems(for: prompt.scopes)) { item in
                    HStack(alignment: .top, spacing: Metric.itemSpacing) {
                        Text("•")
                            .font(.body.weight(.semibold))
                            .frame(width: Metric.iconColumnWidth, alignment: .center)
                            .foregroundStyle(.blue)
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
            }
        }

        private var meaning: some View {
            VStack(alignment: .leading, spacing: Metric.sectionSpacing) {
                Text("What this means")
                    .font(.headline)
                    .foregroundStyle(.primary)
                Text(GCPOAuthLoginPromptCopy.meaningText)
                    .font(.callout)
                    .foregroundStyle(.primary)
                    .fixedSize(horizontal: false, vertical: true)
                Text(GCPOAuthLoginPromptCopy.adminRiskText)
                    .font(.callout)
                    .foregroundStyle(.primary)
                    .fixedSize(horizontal: false, vertical: true)
                Text(GCPOAuthLoginPromptCopy.retryText)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if openCount > 0 {
                    Text("""
                    Google login opened. You can click Open Google Login again if it used the wrong browser profile.
                    """)
                    .font(.callout.weight(.semibold))
                    .foregroundStyle(.blue)
                    .fixedSize(horizontal: false, vertical: true)
                }
                if openFailed {
                    Text("Agent Secret could not open the Google login URL. Check your default browser and try again.")
                        .font(.callout.weight(.semibold))
                        .foregroundStyle(.red)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }

        private var footer: some View {
            HStack(spacing: Metric.footerSpacing) {
                Button("Cancel") {
                    cancel()
                }
                .keyboardShortcut(.cancelAction)

                Spacer()

                Button {
                    if openGoogle() {
                        openCount += 1
                        openFailed = false
                    } else {
                        openFailed = true
                    }
                } label: {
                    Text(openCount == 0 ? "Open Google Login" : "Open Google Login Again")
                        .font(.body.weight(.semibold))
                        .padding(.horizontal, Metric.buttonHorizontalPadding)
                        .padding(.vertical, Metric.buttonVerticalPadding)
                }
                .buttonStyle(.borderedProminent)
                .clipShape(RoundedRectangle(cornerRadius: Metric.buttonCornerRadius))
                .keyboardShortcut(.defaultAction)
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
    }
#endif

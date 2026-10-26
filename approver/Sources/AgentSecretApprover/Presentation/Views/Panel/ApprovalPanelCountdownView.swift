#if canImport(AppKit) && canImport(SwiftUI)
    import AppKit
    import SwiftUI

    struct ApprovalPanelCountdownView: View {
        private typealias Layout = ApprovalPanelLayout

        let countdown: ApprovalCountdown

        @Environment(\.accessibilityReduceMotion)
        private var reduceMotion
        @Environment(\.colorSchemeContrast)
        private var contrast

        var body: some View {
            VStack(spacing: 0) {
                HStack(spacing: Layout.detailSpacing) {
                    Image(systemName: "timer").foregroundStyle(phaseColor).accessibilityHidden(true)
                    Text(countdown.label).foregroundStyle(.secondary)
                    Text(countdown.clock).monospacedDigit()
                        .fontWeight(.semibold)
                        .frame(minWidth: Layout.clockWidth, alignment: .trailing)
                }
                .accessibilityElement(children: .ignore)
                .accessibilityLabel("\(countdown.label) \(countdown.clock)")
            }
        }

        var progress: some View {
            Group {
                if let fraction = countdown.fraction {
                    GeometryReader { proxy in
                        ZStack(alignment: .leading) {
                            phaseColor.opacity(Layout.warningFillOpacity)
                            phaseColor.frame(width: proxy.size.width * fraction)
                        }
                    }
                    .frame(height: contrast == .increased ? Layout.smallSpacing : Layout.labelSpacing)
                    .animation(reduceMotion ? nil : .linear(duration: Layout.barAnimationDuration), value: fraction)
                    .accessibilityHidden(true)
                }
            }
        }

        private var phaseColor: Color {
            switch countdown.phase {
            case .calm:
                Color(nsColor: contrast == .increased ? .labelColor : .systemGreen)

            case .warning:
                Color(nsColor: contrast == .increased ? .labelColor : .systemOrange)

            case .urgent, .expired:
                Color(nsColor: contrast == .increased ? .labelColor : .systemRed)
            }
        }
    }
#endif

import Foundation

#if canImport(SwiftUI)
    import SwiftUI

    struct ApprovalPanelDecisionButton: View {
        private typealias Metric = ApprovalPanelStyle.Metric

        let spec: ApprovalPanelDecisionButtonSpec
        let action: () -> Void

        var body: some View {
            let button = Button(action: action) {
                HStack(spacing: Metric.cautionSpacing) {
                    Image(systemName: spec.icon)
                        .font(.system(size: Metric.buttonIconSize, weight: .semibold))
                        .accessibilityHidden(true)
                    VStack(alignment: .leading, spacing: Metric.detailLabelSpacing) {
                        Text(spec.title)
                            .font(.system(size: Metric.buttonTitleFontSize, weight: .bold))
                            .lineLimit(titleLineLimit)
                            .minimumScaleFactor(Metric.minimumScaleFactor)
                        Text(spec.subtitle)
                            .font(.system(size: Metric.buttonSubtitleFontSize, weight: .medium))
                            .lineLimit(Metric.singleLineLimit)
                            .minimumScaleFactor(Metric.minimumScaleFactor)
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .padding(.horizontal, Metric.buttonHorizontalPadding)
                .foregroundStyle(foregroundColor)
                .background(background)
            }
            .buttonStyle(.plain)

            if let keyboardShortcut: ApprovalPanelKeyboardShortcut = spec.keyboardShortcut {
                button.keyboardShortcut(keyboardShortcut.keyboardShortcut)
            } else {
                button
            }
        }

        private var foregroundColor: Color {
            switch spec.role {
            case .primary:
                .white

            case .secondary:
                .primary
            }
        }

        private var titleLineLimit: Int {
            switch spec.role {
            case .primary:
                Metric.buttonTitleLineLimit

            case .secondary:
                Metric.singleLineLimit
            }
        }

        private var background: some View {
            RoundedRectangle(cornerRadius: Metric.inlineSpacing, style: .continuous)
                .fill(backgroundFill)
                .overlay(
                    RoundedRectangle(cornerRadius: Metric.inlineSpacing, style: .continuous)
                        .stroke(borderColor, lineWidth: Metric.borderWidth)
                )
                .shadow(
                    color: .black.opacity(Metric.buttonShadowOpacity),
                    radius: Metric.buttonShadowRadius,
                    x: Metric.zeroOffset,
                    y: Metric.buttonShadowYOffset
                )
        }

        private var backgroundFill: Color {
            switch spec.role {
            case .primary:
                Color.green

            case .secondary:
                Color.white.opacity(Metric.cardOpacity - Metric.cautionPanelOpacity)
            }
        }

        private var borderColor: Color {
            switch spec.role {
            case .primary:
                Color.green.opacity(Metric.primaryBorderOpacity)

            case .secondary:
                Color.gray.opacity(Metric.secondaryBorderOpacity)
            }
        }
    }
#endif

import Foundation

#if canImport(SwiftUI)
    import SwiftUI

    struct ApprovalPanelReasonCard: View {
        private typealias Metric = ApprovalPanelStyle.Metric
        private typealias Palette = ApprovalPanelStyle.Palette

        let reason: String

        @State private var isExpanded = false
        @State private var measurements = ApprovalPanelReasonMeasurements.Value()

        var body: some View {
            HStack(alignment: .top, spacing: Metric.reasonCardSpacing) {
                reasonIcon
                reasonContent
            }
            .padding(Metric.reasonCardPadding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(panelBackground)
            .overlay(panelBorder)
            .onPreferenceChange(ApprovalPanelReasonMeasurements.Key.self) { measurements = $0 }
        }

        private var reasonIcon: some View {
            Circle()
                .fill(Palette.reasonAccent.opacity(Metric.reasonIconFillOpacity))
                .frame(width: Metric.reasonIconCircleSize, height: Metric.reasonIconCircleSize)
                .overlay {
                    Image(systemName: "bubble.left")
                        .font(.system(size: Metric.reasonIconSize, weight: .medium))
                        .foregroundStyle(Palette.reasonAccent)
                        .accessibilityHidden(true)
                }
        }

        private var reasonContent: some View {
            VStack(alignment: .leading, spacing: Metric.reasonTextSpacing) {
                reasonHeader
                reasonText
            }
            .layoutPriority(Metric.refLayoutPriority)
        }

        @ViewBuilder private var reasonText: some View {
            if reasonTextMode.allowsSelection {
                styledReasonText
                    .textSelection(.enabled)
            } else {
                styledReasonText
            }
        }

        private var styledReasonText: some View {
            Text(reason)
                .font(.system(size: Metric.reasonFontSize, weight: .medium, design: .rounded))
                .foregroundStyle(Palette.reasonText)
                .lineLimit(reasonTextMode.lineLimit)
                .fixedSize(horizontal: false, vertical: true)
                .background(reasonMeasurementViews)
        }

        private var reasonTextMode: ApprovalPanelReasonTextMode {
            ApprovalPanelReasonTextMode(isExpanded: isExpanded)
        }

        private var reasonHeader: some View {
            HStack(alignment: .firstTextBaseline, spacing: Metric.reasonTextSpacing) {
                Text("Reason")
                    .font(.system(size: Metric.sectionLabelFontSize, weight: .semibold))
                    .foregroundStyle(Palette.reasonAccent)
                Spacer(minLength: Metric.reasonTextSpacing)
                expansionButton
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }

        @ViewBuilder private var expansionButton: some View {
            if showsExpansionControl {
                Button(isExpanded ? "Show less" : "Show full reason") {
                    withAnimation(.easeInOut(duration: Metric.reasonExpansionAnimationDuration)) {
                        isExpanded.toggle()
                    }
                }
                .buttonStyle(.plain)
                .font(.system(size: Metric.detailSubtitleFontSize, weight: .semibold))
                .foregroundStyle(Palette.reasonAccent)
                .accessibilityHint(
                    isExpanded ? "Collapses the request reason" : "Reveals the complete request reason"
                )
            }
        }

        private var showsExpansionControl: Bool {
            measurements.fullHeight > measurements.collapsedHeight + Metric.truncationTolerance
        }

        private var reasonMeasurementViews: some View {
            ZStack(alignment: .topLeading) {
                measurementText
                    .lineLimit(Metric.reasonLineLimit)
                    .fixedSize(horizontal: false, vertical: true)
                    .background {
                        GeometryReader { proxy in
                            Color.clear.preference(
                                key: ApprovalPanelReasonMeasurements.Key.self,
                                value: ApprovalPanelReasonMeasurements.Value(collapsedHeight: proxy.size.height)
                            )
                        }
                    }
                measurementText
                    .fixedSize(horizontal: false, vertical: true)
                    .background {
                        GeometryReader { proxy in
                            Color.clear.preference(
                                key: ApprovalPanelReasonMeasurements.Key.self,
                                value: ApprovalPanelReasonMeasurements.Value(fullHeight: proxy.size.height)
                            )
                        }
                    }
            }
            .hidden()
        }

        private var measurementText: some View {
            Text(reason)
                .font(.system(size: Metric.reasonFontSize, weight: .medium, design: .rounded))
        }

        private var panelBackground: some View {
            RoundedRectangle(cornerRadius: Metric.panelCornerRadius, style: .continuous)
                .fill(Palette.reasonAccent.opacity(Metric.reasonPanelOpacity))
        }

        private var panelBorder: some View {
            RoundedRectangle(cornerRadius: Metric.panelCornerRadius, style: .continuous)
                .stroke(Palette.reasonAccent.opacity(Metric.reasonBorderOpacity), lineWidth: Metric.borderWidth)
        }
    }
#endif

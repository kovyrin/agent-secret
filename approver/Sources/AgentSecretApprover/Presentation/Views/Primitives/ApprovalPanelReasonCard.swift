import Foundation

#if canImport(SwiftUI)
    import SwiftUI

    struct ApprovalPanelReasonCard: View {
        private typealias Metric = ApprovalPanelStyle.Metric

        let reason: String
        @Environment(\.accessibilityReduceMotion)
        private var reduceMotion

        @State private var isExpanded = false
        @State private var measurements = ApprovalPanelReasonMeasurements.Value()

        var body: some View {
            HStack(alignment: .top, spacing: Metric.reasonCardSpacing) {
                reasonContent
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .onPreferenceChange(ApprovalPanelReasonMeasurements.Key.self) { measurements = $0 }
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
                .font(.system(size: Metric.reasonFontSize, weight: .regular))
                .foregroundStyle(.primary)
                .lineLimit(reasonTextMode.lineLimit)
                .fixedSize(horizontal: false, vertical: true)
                .background(reasonMeasurementViews)
        }

        private var reasonTextMode: ApprovalPanelReasonTextMode {
            ApprovalPanelReasonTextMode(isExpanded: isExpanded)
        }

        private var reasonHeader: some View {
            HStack(alignment: .firstTextBaseline, spacing: Metric.reasonTextSpacing) {
                Text("Agent's stated reason")
                    .font(.system(size: Metric.sectionLabelFontSize, weight: .semibold))
                    .foregroundStyle(.secondary)
                Spacer(minLength: Metric.reasonTextSpacing)
                expansionButton
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }

        @ViewBuilder private var expansionButton: some View {
            if showsExpansionControl {
                Button(isExpanded ? "Show less" : "Show full reason") {
                    withAnimation(reduceMotion ? nil : .easeInOut(duration: Metric.reasonExpansionAnimationDuration)) {
                        isExpanded.toggle()
                    }
                }
                .buttonStyle(.plain)
                .font(.system(size: Metric.detailSubtitleFontSize, weight: .semibold))
                .foregroundStyle(.secondary)
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
                .font(.system(size: Metric.reasonFontSize, weight: .regular))
        }
    }
#endif

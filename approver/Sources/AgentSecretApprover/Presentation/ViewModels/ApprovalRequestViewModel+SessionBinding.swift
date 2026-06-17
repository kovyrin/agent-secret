import Foundation

extension ApprovalRequestViewModel {
    static func sessionBindingSummary(_ binding: SessionBindingInfo?) -> String? {
        guard let binding else {
            return nil
        }
        return processSummary(binding.boundProcess)
    }

    static func sessionBindingInspectionText(_ binding: SessionBindingInfo?) -> String? {
        guard let binding else {
            return nil
        }
        var lines = [
            "Mode: \(sanitizedDisplayText(binding.mode))"
        ]
        if let ancestorName = binding.ancestorName {
            lines.append("Ancestor name: \(sanitizedDisplayText(ancestorName))")
        }
        if let ancestorDepth = binding.ancestorDepth {
            lines.append("Ancestor depth: \(ancestorDepth)")
        }
        lines.append("Bound process: \(processInspectionLine(binding.boundProcess))")
        lines.append("Creator process: \(processInspectionLine(binding.creatorProcess))")
        return lines.joined(separator: "\n")
    }

    private static func processSummary(_ process: SessionBindingProcess) -> String {
        "\(sanitizedDisplayText(process.name)) pid=\(process.pid)"
    }

    private static func processInspectionLine(_ process: SessionBindingProcess) -> String {
        var parts = [
            "\(sanitizedDisplayText(process.name))",
            "pid=\(process.pid)"
        ]
        if let parentPID = process.parentPID {
            parts.append("ppid=\(parentPID)")
        }
        parts.append("path=\(sanitizedDisplayText(process.path))")
        return parts.joined(separator: " ")
    }
}

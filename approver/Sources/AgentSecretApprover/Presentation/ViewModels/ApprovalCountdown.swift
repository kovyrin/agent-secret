import Foundation

/// Deadline-derived presentation; opening a queued prompt never starts a new lifetime.
struct ApprovalCountdown: Equatable {
    enum Phase: Equatable {
        case calm, warning, urgent, expired
    }

    private static let warningSeconds: TimeInterval = 60
    private static let urgentSeconds: TimeInterval = 15
    private static let secondsPerMinute = 60

    let remaining: TimeInterval
    let fraction: Double?
    let phase: Phase

    var clock: String {
        let seconds = Int(remaining.rounded(.up))
        return String(format: "%d:%02d", seconds / Self.secondsPerMinute, seconds % Self.secondsPerMinute)
    }

    var label: String {
        phase == .calm ? "Answer within" : "Closing in"
    }

    var announcement: String {
        switch phase {
        case .calm:
            "Approval requested."

        case .warning:
            "Approval closes in one minute or less."

        case .urgent:
            "Approval closes in fifteen seconds or less."

        case .expired:
            "Approval request expired."
        }
    }

    init(request: ApprovalRequest, now: Date) {
        let remaining = max(0, request.expiresAt.timeIntervalSince(now))
        self.remaining = remaining
        fraction = request.requestTTLSeconds.flatMap { ttl in
            ttl.isFinite && ttl > 0 ? min(1, max(0, remaining / ttl)) : nil
        }
        if remaining <= 0 {
            phase = .expired
        } else if remaining <= Self.urgentSeconds {
            phase = .urgent
        } else if remaining <= Self.warningSeconds {
            phase = .warning
        } else {
            phase = .calm
        }
    }
}

@testable import AgentSecretApprover
import Foundation
import XCTest

final class ApprovalCommandRenderingTests: XCTestCase {
    private static let sampleExpiration: TimeInterval = 1_800_000_000
    private static let viewModelNow: TimeInterval = 1_799_999_880

    private static func viewModel(
        command: [String],
        resolvedExecutable: String? = nil
    ) -> ApprovalRequestViewModel {
        let request = ApprovalRequest(
            requestID: "req_command",
            nonce: "nonce_command",
            reason: "Review argv",
            command: command,
            cwd: "/tmp/project",
            expiresAt: Date(timeIntervalSince1970: sampleExpiration),
            secrets: [
                RequestedSecret(alias: "DEPLOY_TOKEN", ref: "op://Shared/Deploy/token")
            ],
            resolvedExecutable: resolvedExecutable
        )
        return ApprovalRequestViewModel(
            request: request,
            now: Date(timeIntervalSince1970: viewModelNow)
        )
    }

    func testCompactCommandDisplayShellEscapesEveryArgvElement() {
        let argv = [
            "/bin/echo",
            "hello world",
            "it's",
            "line\nbreak",
            "--flag",
            "$(rm -rf /)",
            "snowman ☃",
            "bell\u{0007}",
            "\u{001F}unit"
        ]
        let viewModel = Self.viewModel(command: argv)

        XCTAssertEqual(
            viewModel.command,
            "'/bin/echo' 'hello world' 'it'\\''s' $'line\\nbreak' '--flag' " +
                "'$(rm -rf /)' 'snowman ☃' $'bell\\a' $'\\x1Funit'"
        )
        XCTAssertNotEqual(viewModel.command, argv.joined(separator: " "))
        XCTAssertFalse(viewModel.command.contains("\n"))
        XCTAssertFalse(viewModel.command.contains("\u{0007}"))
        XCTAssertFalse(viewModel.command.contains("\u{001F}"))
    }

    func testStructuredCommandInspectorPreservesArgvBoundaries() {
        let viewModel = Self.viewModel(command: [
            "/usr/bin/env",
            "NAME=value with space",
            "--",
            "printf",
            "%s\n",
            "emoji-🚀"
        ])

        XCTAssertTrue(viewModel.commandNeedsInspector)
        XCTAssertEqual(viewModel.commandArguments.map(\.index), [0, 1, 2, 3, 4, 5])
        XCTAssertTrue(viewModel.commandInspectionText.contains("argv[1]: 'NAME=value with space'"))
        XCTAssertTrue(viewModel.commandInspectionText.contains("argv[2]: '--'"))
        XCTAssertTrue(viewModel.commandInspectionText.contains("argv[4]: $'%s\\n'"))
        XCTAssertTrue(viewModel.commandInspectionText.contains("argv[5]: 'emoji-🚀'"))
    }

    func testCommandDisplayKeepsOriginalArgvZeroSeparateFromResolvedBinary() {
        let viewModel = Self.viewModel(
            command: ["terraform", "plan"],
            resolvedExecutable: "/opt/homebrew/bin/terraform"
        )

        XCTAssertEqual(viewModel.command, "'terraform' 'plan'")
        XCTAssertTrue(viewModel.renderedText.contains("Resolved binary: /opt/homebrew/bin/terraform"))
    }

    deinit {
        /* Required by SwiftLint. */
    }
}

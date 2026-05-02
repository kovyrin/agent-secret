import Foundation

#if canImport(AppKit)
    import AppKit
#endif

private let kSetupInstallButton: NSApplication.ModalResponse = .alertFirstButtonReturn
private let kSetupDoctorButton: NSApplication.ModalResponse = .alertSecondButtonReturn

@MainActor
func runSetupDialog() {
    #if canImport(AppKit)
        let app = NSApplication.shared
        app.setActivationPolicy(.regular)
        NSRunningApplication.current.activate(options: [.activateAllWindows])

        var message = setupIntroText()
        var shouldContinue = true
        while shouldContinue {
            let alert = NSAlert()
            alert.messageText = "Agent Secret"
            alert.informativeText = message
            alert.alertStyle = .informational
            alert.addButton(withTitle: "Install Command Line Tool")
            alert.addButton(withTitle: "Run Diagnostics")
            alert.addButton(withTitle: "Quit")

            switch alert.runModal() {
            case kSetupInstallButton:
                message = runBundledAgentSecret(arguments: ["install-cli"])

            case kSetupDoctorButton:
                message = runBundledAgentSecret(arguments: ["doctor"])

            default:
                shouldContinue = false
            }
        }
        app.terminate(nil)
    #else
        /* AppKit is required for the setup dialog. */
    #endif
}

private func setupIntroText() -> String {
    """
    Agent Secret is installed as a macOS app with the command-line tool bundled inside it.

    Install Command Line Tool creates or repairs the agent-secret command symlink for this user.
    Run Diagnostics prints non-secret local setup information.
    """
}

private func runBundledAgentSecret(arguments: [String]) -> String {
    guard let cliPath = bundledAgentSecretPath() else {
        return """
        The bundled agent-secret command was not found inside this app.

        Reinstall Agent Secret.app, then open the app again.
        """
    }

    let process = Process()
    process.executableURL = URL(fileURLWithPath: cliPath)
    process.arguments = arguments

    let outputPipe = Pipe()
    process.standardOutput = outputPipe
    process.standardError = outputPipe

    do {
        try process.run()
        process.waitUntilExit()
    } catch {
        return "Could not run \(cliPath): \(error)"
    }

    let data = outputPipe.fileHandleForReading.readDataToEndOfFile()
    let output = (String(bytes: data, encoding: .utf8) ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
    if process.terminationStatus == 0 {
        return output.isEmpty ? "Command completed." : output
    }
    if output.isEmpty {
        return "agent-secret \(arguments.joined(separator: " ")) failed with exit \(process.terminationStatus)."
    }
    return output
}

private func bundledAgentSecretPath() -> String? {
    let candidate = URL(fileURLWithPath: Bundle.main.bundlePath)
        .appendingPathComponent("Contents")
        .appendingPathComponent("Resources")
        .appendingPathComponent("bin")
        .appendingPathComponent("agent-secret")
        .path

    return FileManager.default.isExecutableFile(atPath: candidate) ? candidate : nil
}

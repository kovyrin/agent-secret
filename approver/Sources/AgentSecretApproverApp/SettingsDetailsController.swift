import AppKit

@MainActor
final class SettingsDetailsController: NSWindowController, NSWindowDelegate {
    private enum Metric {
        static let width: CGFloat = 500
        static let height: CGFloat = 320
        static let minimumWidth: CGFloat = 420
        static let minimumHeight: CGFloat = 260
        static let margin: CGFloat = 24
        static let top: CGFloat = 20
        static let bottom: CGFloat = 18
        static let headingGap: CGFloat = 14
        static let buttonGap: CGFloat = 16
        static let textInset: CGFloat = 10
        static let fontSize: CGFloat = 11
        static let outputWidth: CGFloat = 452
    }

    init(title: String, summary: String, output: String) {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: Metric.width, height: Metric.height),
            styleMask: [.titled, .closable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = title
        window.minSize = NSSize(width: Metric.minimumWidth, height: Metric.minimumHeight)
        window.isReleasedWhenClosed = false
        window.isRestorable = false
        super.init(window: window)
        window.delegate = self
        buildContent(summary: summary, output: output)
    }

    @available(*, unavailable)
    required init?(coder _: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func windowShouldClose(_: NSWindow) -> Bool {
        dismiss()
        return false
    }

    private func buildContent(summary: String, output: String) {
        guard let content = window?.contentView else {
            return
        }
        let heading = NSTextField(labelWithString: summary)
        heading.font = .systemFont(ofSize: NSFont.systemFontSize, weight: .semibold)
        let scroll = outputView(output)
        let close = NSButton(title: "Done", target: self, action: #selector(dismiss))
        close.bezelStyle = .rounded
        close.keyEquivalent = "\r"
        for view in [heading, scroll, close] {
            view.translatesAutoresizingMaskIntoConstraints = false
            content.addSubview(view)
        }
        NSLayoutConstraint.activate([
            heading.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: Metric.margin),
            heading.topAnchor.constraint(equalTo: content.topAnchor, constant: Metric.top),
            heading.trailingAnchor.constraint(lessThanOrEqualTo: content.trailingAnchor, constant: -Metric.margin),
            scroll.leadingAnchor.constraint(equalTo: heading.leadingAnchor),
            scroll.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -Metric.margin),
            scroll.topAnchor.constraint(equalTo: heading.bottomAnchor, constant: Metric.headingGap),
            scroll.bottomAnchor.constraint(equalTo: close.topAnchor, constant: -Metric.buttonGap),
            close.trailingAnchor.constraint(equalTo: scroll.trailingAnchor),
            close.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -Metric.bottom)
        ])
    }

    private func outputView(_ output: String) -> NSScrollView {
        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.borderType = .bezelBorder
        let text = NSTextView(frame: NSRect(x: 0, y: 0, width: Metric.outputWidth, height: 0))
        text.isEditable = false
        text.isSelectable = true
        text.isRichText = false
        text.font = .monospacedSystemFont(ofSize: Metric.fontSize, weight: .regular)
        text.textColor = .textColor
        text.backgroundColor = .textBackgroundColor
        text.textContainerInset = NSSize(width: Metric.textInset, height: Metric.textInset)
        text.isVerticallyResizable = true
        text.isHorizontallyResizable = false
        text.autoresizingMask = .width
        text.textContainer?.widthTracksTextView = true
        text.string = output
        scroll.documentView = text
        return scroll
    }

    @objc
    private func dismiss() {
        guard let window else {
            return
        }
        window.sheetParent?.endSheet(window)
        window.orderOut(nil)
    }
}

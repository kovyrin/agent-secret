import AppKit

guard CommandLine.arguments.count == 2 else {
  FileHandle.standardError.write(Data("usage: make-daemon-icon.swift <png-path>\n".utf8))
  exit(2)
}

let size = NSSize(width: 1024, height: 1024)
let image = NSImage(size: size)

image.lockFocus()

NSColor(calibratedRed: 0.08, green: 0.18, blue: 0.27, alpha: 1).setFill()
NSBezierPath(roundedRect: NSRect(origin: .zero, size: size), xRadius: 220, yRadius: 220).fill()

NSColor(calibratedRed: 0.16, green: 0.68, blue: 0.62, alpha: 1).setFill()
NSBezierPath(ovalIn: NSRect(x: 232, y: 548, width: 282, height: 282)).fill()

NSColor(calibratedWhite: 0.95, alpha: 1).setFill()
NSBezierPath(ovalIn: NSRect(x: 302, y: 618, width: 142, height: 142)).fill()

let shaft = NSBezierPath(roundedRect: NSRect(x: 492, y: 654, width: 330, height: 72), xRadius: 36, yRadius: 36)
shaft.fill()
NSBezierPath(rect: NSRect(x: 682, y: 546, width: 62, height: 140)).fill()
NSBezierPath(rect: NSRect(x: 786, y: 546, width: 62, height: 140)).fill()

let paragraph = NSMutableParagraphStyle()
paragraph.alignment = .center
let attrs: [NSAttributedString.Key: Any] = [
  .font: NSFont.systemFont(ofSize: 188, weight: .heavy),
  .foregroundColor: NSColor(calibratedWhite: 0.95, alpha: 1),
  .paragraphStyle: paragraph,
]
"AS".draw(in: NSRect(x: 0, y: 142, width: 1024, height: 240), withAttributes: attrs)

image.unlockFocus()

guard
  let tiff = image.tiffRepresentation,
  let bitmap = NSBitmapImageRep(data: tiff),
  let png = bitmap.representation(using: .png, properties: [:])
else {
  FileHandle.standardError.write(Data("failed to encode icon\n".utf8))
  exit(1)
}

try png.write(to: URL(fileURLWithPath: CommandLine.arguments[1]))

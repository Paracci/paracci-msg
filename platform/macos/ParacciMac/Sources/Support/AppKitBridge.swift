import AppKit
import SwiftUI
import UniformTypeIdentifiers

struct WindowSharingProtection: NSViewRepresentable {
    func makeNSView(context: Context) -> NSView {
        ProtectedWindowHost()
    }

    func updateNSView(_ nsView: NSView, context: Context) {}
}

private final class ProtectedWindowHost: NSView {
    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        window?.sharingType = .none
    }
}

enum SecureClipboard {
    static func copy(_ text: String, clearAfter seconds: TimeInterval = 20) {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(text, forType: .string)

        DispatchQueue.main.asyncAfter(deadline: .now() + seconds) {
            if pasteboard.string(forType: .string) == text {
                pasteboard.clearContents()
            }
        }
    }
}

enum NativeFilePanel {
    static func openParacciFile(title: String) -> URL? {
        let panel = NSOpenPanel()
        panel.title = title
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        if let paracciType = UTType(filenameExtension: "paracci") {
            panel.allowedContentTypes = [paracciType]
        }
        return panel.runModal() == .OK ? panel.url : nil
    }

    static func openAttachmentFiles() -> [URL] {
        let panel = NSOpenPanel()
        panel.title = "Choose Attachments"
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = true
        return panel.runModal() == .OK ? panel.urls : []
    }

    static func saveParacciFile(title: String, suggestedName: String) -> URL? {
        let panel = NSSavePanel()
        panel.title = title
        panel.nameFieldStringValue = suggestedName
        panel.canCreateDirectories = true
        if let paracciType = UTType(filenameExtension: "paracci") {
            panel.allowedContentTypes = [paracciType]
        }
        return panel.runModal() == .OK ? panel.url : nil
    }

    static func saveAttachment(name: String) -> URL? {
        let panel = NSSavePanel()
        panel.title = "Save Attachment"
        panel.nameFieldStringValue = name
        panel.canCreateDirectories = true
        return panel.runModal() == .OK ? panel.url : nil
    }
}

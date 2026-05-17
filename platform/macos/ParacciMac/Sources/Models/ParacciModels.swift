import Foundation

enum AppRoute: String, Hashable, CaseIterable {
    case sessions
    case newSession
    case importSession
    case settings
    case armorReport
}

struct SessionSummary: Identifiable, Hashable {
    let id: String
    var label: String
    var role: String
    var state: String
    var updatedText: String
    var fingerprint: String

    static let placeholder = SessionSummary(
        id: "placeholder",
        label: "No Session Selected",
        role: "-",
        state: "Unavailable",
        updatedText: "",
        fingerprint: "-"
    )
}

struct OpenedAttachment: Identifiable, Hashable {
    var id: String
    var name: String
    var mime: String
    var sizeText: String
    var allowDownload: Bool
    var previewText: String?
}

struct OpenedMessage: Hashable {
    var openID: String?
    var text: String
    var allowDownload: Bool
    var attachments: [OpenedAttachment]

    static let empty = OpenedMessage(openID: nil, text: "", allowDownload: false, attachments: [])
}

struct InspectorRow: Identifiable, Hashable {
    let id = UUID()
    var title: String
    var value: String
    var tone: StatusTone = .neutral
}

enum StatusTone: String, Hashable {
    case neutral
    case protected
    case bestEffort
    case warning
    case critical
}

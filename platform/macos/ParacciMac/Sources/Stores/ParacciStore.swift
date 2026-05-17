import Foundation

@MainActor
final class ParacciStore: ObservableObject {
    @Published var route: AppRoute = .sessions
    @Published var sessions: [SessionSummary] = []
    @Published var selection: SessionSummary.ID?
    @Published var openedMessage: OpenedMessage = .empty
    @Published var searchText = ""
    @Published var statusText = "Starting"
    @Published var isUnlocked = false
    @Published var isInitialized = false
    @Published var themeMode = "system"
    @Published var armorReport = ""
    @Published var workflowLabel = ""

    private let client = PythonWorkerClient()

    var selectedSession: SessionSummary {
        sessions.first(where: { $0.id == selection }) ?? .placeholder
    }

    var filteredSessions: [SessionSummary] {
        guard !searchText.isEmpty else { return sessions }
        return sessions.filter {
            $0.label.localizedCaseInsensitiveContains(searchText) ||
            $0.id.localizedCaseInsensitiveContains(searchText)
        }
    }

    var inspectorRows: [InspectorRow] {
        let session = selectedSession
        return [
            InspectorRow(title: "State", value: session.state, tone: session.state == "active" ? .protected : .warning),
            InspectorRow(title: "Role", value: session.role),
            InspectorRow(title: "Fingerprint", value: session.fingerprint),
            InspectorRow(title: "Anti-screenshot", value: "Best effort", tone: .bestEffort),
            InspectorRow(title: "Download Policy", value: openedMessage.allowDownload ? "Allowed" : "Blocked", tone: openedMessage.allowDownload ? .neutral : .warning)
        ]
    }

    func start() async {
        await refreshStatus()
        if isUnlocked {
            await refreshSessions()
        }
    }

    func refreshStatus() async {
        do {
            let result = try await client.call(method: "device_status")
            isInitialized = result["initialized"] as? Bool ?? false
            isUnlocked = result["unlocked"] as? Bool ?? false
            statusText = isUnlocked ? "Protected" : "Locked"
        } catch {
            statusText = error.localizedDescription
        }
    }

    func unlock(pin: String) async {
        do {
            _ = try await client.call(method: "device_unlock", params: ["pin": pin])
            await refreshStatus()
            await refreshSessions()
        } catch {
            statusText = error.localizedDescription
        }
    }

    func initialize(pin: String) async {
        do {
            _ = try await client.call(method: "device_init", params: ["pin": pin])
            await refreshStatus()
            await refreshSessions()
        } catch {
            statusText = error.localizedDescription
        }
    }

    func lock() async {
        do {
            _ = try await client.call(method: "device_lock")
            isUnlocked = false
            selection = nil
            openedMessage = .empty
            statusText = "Locked"
        } catch {
            statusText = error.localizedDescription
        }
    }

    func refreshSessions() async {
        do {
            let result = try await client.call(method: "sessions_list")
            let rows = result["sessions"] as? [[String: Any]] ?? []
            sessions = rows.map { row in
                SessionSummary(
                    id: row["session_id_hex"] as? String ?? UUID().uuidString,
                    label: row["label"] as? String ?? "Untitled",
                    role: row["role"] as? String ?? "-",
                    state: row["state"] as? String ?? "unknown",
                    updatedText: row["updated_text"] as? String ?? "",
                    fingerprint: row["fingerprint"] as? String ?? "-"
                )
            }
            if selection == nil {
                selection = sessions.first?.id
            }
            statusText = "Protected"
        } catch {
            statusText = error.localizedDescription
        }
    }

    func loadArmorReport() async {
        do {
            let result = try await client.call(method: "armor_report_load")
            armorReport = result["markdown"] as? String ?? ""
            route = .armorReport
        } catch {
            statusText = error.localizedDescription
        }
    }

    func createSession(label: String, profile: String, exportURL: URL) async {
        do {
            let result = try await client.call(
                method: "session_create",
                params: [
                    "label": label.trimmingCharacters(in: .whitespacesAndNewlines),
                    "profile": profile,
                    "export_path": exportURL.path
                ]
            )
            statusText = result["message"] as? String ?? "Session created"
            selection = result["session_id_hex"] as? String
            route = .sessions
            await refreshSessions()
        } catch {
            statusText = error.localizedDescription
        }
    }

    func importSession(importURL: URL, localLabel: String, autoExportURL: URL?) async {
        do {
            var params: [String: Any] = [
                "import_path": importURL.path,
                "local_label": localLabel.trimmingCharacters(in: .whitespacesAndNewlines)
            ]
            if let autoExportURL {
                params["auto_export_path"] = autoExportURL.path
            }

            let result = try await client.call(method: "session_import", params: params)
            statusText = result["message"] as? String ?? "Session imported"
            selection = result["session_id_hex"] as? String
            route = .sessions
            await refreshSessions()
        } catch {
            statusText = error.localizedDescription
        }
    }

    func sealMessage(text: String, allowDownload: Bool, attachmentURLs: [URL], outputURL: URL) async {
        guard let sessionID = selection else {
            statusText = "Select a session before sealing."
            return
        }

        do {
            _ = try await client.call(
                method: "message_seal",
                params: [
                    "session_id_hex": sessionID,
                    "text": text,
                    "output_path": outputURL.path,
                    "attachment_paths": attachmentURLs.map(\.path),
                    "allow_download": allowDownload
                ]
            )
            statusText = "Message sealed"
            await refreshSessions()
        } catch {
            statusText = error.localizedDescription
        }
    }

    func openMessage(fileURL: URL) async {
        guard let sessionID = selection else {
            statusText = "Select a session before opening."
            return
        }

        do {
            let result = try await client.call(
                method: "message_open",
                params: [
                    "session_id_hex": sessionID,
                    "message_path": fileURL.path,
                    "burn_source": true
                ]
            )
            openedMessage = openedMessage(from: result)
            statusText = "Message opened"
            await refreshSessions()
        } catch {
            statusText = error.localizedDescription
        }
    }

    func clearOpenedMessage() async {
        if let openID = openedMessage.openID {
            do {
                _ = try await client.call(method: "open_clear", params: ["open_id": openID])
            } catch {
                statusText = error.localizedDescription
            }
        }
        openedMessage = .empty
    }

    func saveAttachment(_ attachment: OpenedAttachment, to outputURL: URL) async {
        guard let openID = openedMessage.openID else {
            statusText = "No opened message is active."
            return
        }
        guard attachment.allowDownload else {
            statusText = "The sender blocked attachment saving."
            return
        }

        do {
            _ = try await client.call(
                method: "attachment_save",
                params: [
                    "open_id": openID,
                    "attachment_id": attachment.id,
                    "output_path": outputURL.path
                ]
            )
            statusText = "Attachment saved"
        } catch {
            statusText = error.localizedDescription
        }
    }

    private func openedMessage(from result: [String: Any]) -> OpenedMessage {
        let attachments = (result["attachments"] as? [[String: Any]] ?? []).map { row in
            OpenedAttachment(
                id: row["attachment_id"] as? String ?? "",
                name: row["filename"] as? String ?? "Attachment",
                mime: row["mime_type"] as? String ?? "application/octet-stream",
                sizeText: Self.formatBytes(row["size"] as? Int ?? 0),
                allowDownload: row["allow_download"] as? Bool ?? false,
                previewText: nil
            )
        }
        return OpenedMessage(
            openID: result["open_id"] as? String,
            text: result["text"] as? String ?? "",
            allowDownload: result["allow_download"] as? Bool ?? false,
            attachments: attachments
        )
    }

    private static func formatBytes(_ bytes: Int) -> String {
        let formatter = ByteCountFormatter()
        formatter.allowedUnits = [.useKB, .useMB, .useGB]
        formatter.countStyle = .file
        return formatter.string(fromByteCount: Int64(bytes))
    }
}

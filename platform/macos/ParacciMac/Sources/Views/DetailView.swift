import SwiftUI

struct DetailView: View {
    @ObservedObject var store: ParacciStore
    @State private var pin = ""

    var body: some View {
        Group {
            if !store.isInitialized {
                AuthenticationView(
                    title: "Initialize Paracci",
                    subtitle: "Create the local device key for this Mac.",
                    actionTitle: "Create Device",
                    pin: $pin
                ) {
                    Task { await store.initialize(pin: pin) }
                }
            } else if !store.isUnlocked {
                AuthenticationView(
                    title: "Unlock Paracci",
                    subtitle: "Unlock encrypted metadata stored on this Mac.",
                    actionTitle: "Unlock",
                    pin: $pin
                ) {
                    Task { await store.unlock(pin: pin) }
                }
            } else {
                switch store.route {
                case .sessions:
                    SessionDetailView(store: store)
                case .newSession:
                    NewSessionView(store: store)
                case .importSession:
                    ImportSessionView(store: store)
                case .settings:
                    SettingsView(store: store)
                case .armorReport:
                    ArmorReportView(markdown: store.armorReport)
                }
            }
        }
        .padding(20)
    }
}

struct AuthenticationView: View {
    var title: String
    var subtitle: String
    var actionTitle: String
    @Binding var pin: String
    var action: () -> Void

    var body: some View {
        VStack(spacing: 18) {
            Image(systemName: "lock.shield")
                .font(.system(size: 42))
                .foregroundStyle(.blue)
            Text(title)
                .font(.title)
                .fontWeight(.semibold)
            Text(subtitle)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            SecureField("PIN", text: $pin)
                .textFieldStyle(.roundedBorder)
                .frame(width: 280)
                .onSubmit(action)
            Button(actionTitle, action: action)
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

struct SessionDetailView: View {
    @ObservedObject var store: ParacciStore

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(store.selectedSession.label)
                            .font(.largeTitle)
                            .fontWeight(.semibold)
                        Text(store.selectedSession.id)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }
                    Spacer()
                    StatusPillView(text: store.selectedSession.state, tone: .protected)
                }

                ComposerCard(store: store)
                ReadingRoomView(store: store, message: store.openedMessage)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

struct ComposerCard: View {
    @ObservedObject var store: ParacciStore
    @State private var message = ""
    @State private var allowSave = false
    @State private var attachments: [URL] = []

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Composer")
                    .font(.headline)
                Spacer()
                if !attachments.isEmpty {
                    Text("\(attachments.count) attachment(s)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            TextEditor(text: $message)
                .frame(minHeight: 150)
                .scrollContentBackground(.hidden)
            HStack {
                Toggle("Allow save", isOn: $allowSave)
                Spacer()
                Button {
                    attachments = NativeFilePanel.openAttachmentFiles()
                } label: {
                    Label("Attach", systemImage: "paperclip")
                }
                Button {
                    if let url = NativeFilePanel.saveParacciFile(title: "Save Sealed Message", suggestedName: "message.paracci") {
                        Task { await store.sealMessage(text: message, allowDownload: allowSave, attachmentURLs: attachments, outputURL: url) }
                    }
                } label: {
                    Label("Seal", systemImage: "lock.doc")
                }
                    .buttonStyle(.borderedProminent)
            }
        }
        .padding()
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
    }
}

struct ReadingRoomView: View {
    @ObservedObject var store: ParacciStore
    var message: OpenedMessage

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Reading Room")
                    .font(.headline)
                Spacer()
                StatusPillView(text: message.openID == nil ? "Empty" : "Protected", tone: message.openID == nil ? .neutral : .protected)
            }
            Text(displayText)
                .foregroundStyle(message.text.isEmpty ? .secondary : .primary)
                .frame(maxWidth: .infinity, minHeight: 160, alignment: .topLeading)
            Divider()
            HStack {
                Text("\(message.attachments.count) attachment(s)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Open File") {
                    if let url = NativeFilePanel.openParacciFile(title: "Open Message") {
                        Task { await store.openMessage(fileURL: url) }
                    }
                }
                Button("Clear") {
                    Task { await store.clearOpenedMessage() }
                }
                .disabled(message.openID == nil)
            }
            ForEach(message.attachments) { attachment in
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(attachment.name)
                            .lineLimit(1)
                        Text("\(attachment.mime) / \(attachment.sizeText)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    StatusPillView(
                        text: attachment.allowDownload ? "Allowed" : "Blocked",
                        tone: attachment.allowDownload ? .neutral : .warning
                    )
                    Button("Save") {
                        if let url = NativeFilePanel.saveAttachment(name: attachment.name) {
                            Task { await store.saveAttachment(attachment, to: url) }
                        }
                    }
                    .disabled(!attachment.allowDownload)
                }
                .padding(.vertical, 4)
            }
        }
        .padding()
        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
    }

    private var displayText: AttributedString {
        if message.text.isEmpty {
            return AttributedString("Opened messages appear here.")
        }
        return (try? AttributedString(markdown: message.text)) ?? AttributedString(message.text)
    }
}

struct NewSessionView: View {
    @ObservedObject var store: ParacciStore
    @State private var label = ""
    @State private var profile = "standard"

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("New Session")
                .font(.largeTitle)
                .fontWeight(.semibold)
            Text("Create an initiator file using a native save panel.")
                .foregroundStyle(.secondary)
            TextField("Session label", text: $label)
                .textFieldStyle(.roundedBorder)
                .frame(maxWidth: 420)
            Picker("Profile", selection: $profile) {
                Text("Standard").tag("standard")
                Text("Paranoid").tag("paranoid")
                Text("Quantum").tag("quantum")
                Text("Custom").tag("custom")
            }
            .pickerStyle(.segmented)
            .frame(maxWidth: 420)
            Button {
                if let url = NativeFilePanel.saveParacciFile(title: "Save Initiator", suggestedName: "session_init.paracci") {
                    Task { await store.createSession(label: label.isEmpty ? "New Session" : label, profile: profile, exportURL: url) }
                }
            } label: {
                Label("Create and Export", systemImage: "square.and.arrow.up")
            }
            .buttonStyle(.borderedProminent)
            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
}

struct ImportSessionView: View {
    @ObservedObject var store: ParacciStore
    @State private var label = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Import")
                .font(.largeTitle)
                .fontWeight(.semibold)
            Text("Import a handshake file and choose a response save path when one is produced.")
                .foregroundStyle(.secondary)
            TextField("Local label", text: $label)
                .textFieldStyle(.roundedBorder)
                .frame(maxWidth: 420)
            Button {
                guard let importURL = NativeFilePanel.openParacciFile(title: "Import Paracci File") else {
                    return
                }
                let responseURL = NativeFilePanel.saveParacciFile(title: "Save Response If Needed", suggestedName: "session_response.paracci")
                Task { await store.importSession(importURL: importURL, localLabel: label, autoExportURL: responseURL) }
            } label: {
                Label("Import", systemImage: "square.and.arrow.down")
            }
            .buttonStyle(.borderedProminent)
            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
}

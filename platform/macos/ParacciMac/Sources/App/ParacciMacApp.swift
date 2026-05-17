import SwiftUI

@main
struct ParacciMacApp: App {
    @StateObject private var store = ParacciStore()
    @State private var isInspectorVisible = true

    var body: some Scene {
        WindowGroup("Paracci Secure Messaging") {
            ContentView(store: store, isInspectorVisible: $isInspectorVisible)
                .frame(minWidth: 980, minHeight: 640)
                .background(WindowSharingProtection())
                .task {
                    await store.start()
                }
        }
        .commands {
            CommandGroup(after: .newItem) {
                Button("New Session") {
                    store.route = .newSession
                }
                .keyboardShortcut("n")

                Button("Import") {
                    store.route = .importSession
                }
                .keyboardShortcut("o")
            }

            CommandMenu("Security") {
                Button("Lock") {
                    Task { await store.lock() }
                }
                .keyboardShortcut("l")

                Toggle("Show Inspector", isOn: $isInspectorVisible)
                    .keyboardShortcut("i", modifiers: [.command, .option])
            }
        }

        Settings {
            SettingsView(store: store)
                .frame(width: 520)
        }
    }
}

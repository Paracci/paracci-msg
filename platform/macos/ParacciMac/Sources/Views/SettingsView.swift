import SwiftUI

struct SettingsView: View {
    @ObservedObject var store: ParacciStore

    var body: some View {
        Form {
            Section("Appearance") {
                Picker("Theme", selection: $store.themeMode) {
                    Text("System").tag("system")
                    Text("Dark").tag("dark")
                    Text("Light").tag("light")
                }
                .pickerStyle(.segmented)
            }

            Section("Security") {
                LabeledContent("Anti-screenshot") {
                    StatusPillView(text: "Best effort", tone: .bestEffort)
                }
                LabeledContent("Clipboard") {
                    Text("Clears after short delay")
                        .foregroundStyle(.secondary)
                }
                LabeledContent("Downloads") {
                    Text("Controlled by sender policy")
                        .foregroundStyle(.secondary)
                }
            }
        }
        .formStyle(.grouped)
        .padding()
    }
}

import SwiftUI

struct SidebarView: View {
    @ObservedObject var store: ParacciStore

    var body: some View {
        List(selection: $store.selection) {
            Section("Sessions") {
                ForEach(store.filteredSessions) { session in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(session.label)
                            .lineLimit(1)
                        Text(session.updatedText.isEmpty ? session.role : session.updatedText)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }
                    .tag(session.id)
                }
            }
        }
        .listStyle(.sidebar)
        .safeAreaInset(edge: .bottom) {
            VStack(alignment: .leading, spacing: 6) {
                StatusPillView(text: store.statusText, tone: store.isUnlocked ? .protected : .warning)
                Text("Offline file-based transport")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding()
        }
    }
}

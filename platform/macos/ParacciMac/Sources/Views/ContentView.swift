import SwiftUI

struct ContentView: View {
    @ObservedObject var store: ParacciStore
    @Binding var isInspectorVisible: Bool

    var body: some View {
        NavigationSplitView {
            SidebarView(store: store)
        } detail: {
            HSplitView {
                DetailView(store: store)
                    .frame(minWidth: 520)

                if isInspectorVisible {
                    InspectorView(rows: store.inspectorRows)
                        .frame(minWidth: 260, idealWidth: 300, maxWidth: 360)
                }
            }
        }
        .searchable(text: $store.searchText, placement: .toolbar, prompt: "Search sessions")
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                Button {
                    store.route = .newSession
                } label: {
                    Label("New", systemImage: "plus")
                }

                Button {
                    store.route = .importSession
                } label: {
                    Label("Import", systemImage: "square.and.arrow.down")
                }

                Button {
                    Task { await store.loadArmorReport() }
                } label: {
                    Label("Armor Report", systemImage: "shield.lefthalf.filled")
                }

                Button {
                    Task { await store.lock() }
                } label: {
                    Label("Lock", systemImage: "lock")
                }
            }
        }
    }
}

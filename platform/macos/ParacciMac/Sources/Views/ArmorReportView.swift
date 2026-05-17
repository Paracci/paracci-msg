import SwiftUI

struct ArmorReportView: View {
    var markdown: String

    var body: some View {
        ScrollView {
            Text(markdown.isEmpty ? "Armor report has not been loaded." : markdown)
                .frame(maxWidth: .infinity, alignment: .leading)
                .textSelection(.enabled)
                .padding()
        }
    }
}

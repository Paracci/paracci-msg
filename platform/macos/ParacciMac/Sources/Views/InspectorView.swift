import SwiftUI

struct InspectorView: View {
    var rows: [InspectorRow]

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                Text("Inspector")
                    .font(.headline)
                    .padding(.bottom, 4)

                ForEach(rows) { row in
                    VStack(alignment: .leading, spacing: 4) {
                        Text(row.title)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        HStack {
                            Text(row.value)
                                .lineLimit(2)
                            Spacer()
                            Circle()
                                .fill(color(for: row.tone))
                                .frame(width: 8, height: 8)
                        }
                    }
                    Divider()
                }
            }
            .padding()
        }
        .background(.bar)
    }

    private func color(for tone: StatusTone) -> Color {
        switch tone {
        case .protected:
            return .green
        case .bestEffort:
            return .blue
        case .warning:
            return .orange
        case .critical:
            return .red
        case .neutral:
            return .secondary
        }
    }
}

import SwiftUI

struct StatusPillView: View {
    var text: String
    var tone: StatusTone

    var body: some View {
        Text(text.isEmpty ? "Unavailable" : text.capitalized)
            .font(.caption)
            .fontWeight(.medium)
            .padding(.horizontal, 9)
            .padding(.vertical, 4)
            .background(background, in: Capsule())
            .foregroundStyle(foreground)
    }

    private var background: Color {
        switch tone {
        case .protected:
            return .green.opacity(0.18)
        case .bestEffort:
            return .blue.opacity(0.18)
        case .warning:
            return .orange.opacity(0.18)
        case .critical:
            return .red.opacity(0.18)
        case .neutral:
            return .secondary.opacity(0.14)
        }
    }

    private var foreground: Color {
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

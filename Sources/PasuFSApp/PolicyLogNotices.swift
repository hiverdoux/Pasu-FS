import SwiftUI

/// Keeps the table at a stable height while retaining the full text of every current issue.
struct PolicyLogNotices: View {
  let notices: [PolicyLogNotice]
  @State private var isPresented = false

  var body: some View {
    if let first = notices.first {
      Button {
        isPresented.toggle()
      } label: {
        HStack(spacing: 6) {
          Image(systemName: symbol(first))
            .foregroundStyle(tint(first))
          Text(first.message)
            .lineLimit(1)
            .truncationMode(.tail)
          if notices.count > 1 {
            Text("\(notices.count) issues")
              .monospacedDigit()
              .fixedSize()
          }
          Image(systemName: "chevron.down")
            .font(.caption2)
        }
        .font(.caption)
        .contentShape(Rectangle())
      }
      .buttonStyle(.plain)
      .help("Show log errors and warnings")
      .accessibilityLabel(Text("Show log errors and warnings"))
      .accessibilityValue(Text("\(notices.count) issues: \(first.message)"))
      .popover(isPresented: $isPresented, arrowEdge: .bottom) {
        VStack(alignment: .leading, spacing: 12) {
          Text("Log Errors and Warnings")
            .font(.headline)
          ScrollView {
            VStack(alignment: .leading, spacing: 12) {
              ForEach(notices) { notice in
                HStack(alignment: .top, spacing: 8) {
                  Image(systemName: symbol(notice))
                    .foregroundStyle(tint(notice))
                    .accessibilityLabel(
                      notice.severity == .error ? Text("Error") : Text("Warning"))
                  Text(notice.message)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .fixedSize(horizontal: false, vertical: true)
                    .textSelection(.enabled)
                }
                if notice.id != notices.last?.id { Divider() }
              }
            }
          }
          .frame(maxHeight: 320)
        }
        .padding()
        .frame(width: 420)
      }
      .onChange(of: notices.isEmpty) {
        if notices.isEmpty { isPresented = false }
      }
    }
  }

  private func symbol(_ notice: PolicyLogNotice) -> String {
    notice.severity == .error ? "exclamationmark.circle.fill" : "exclamationmark.triangle.fill"
  }

  private func tint(_ notice: PolicyLogNotice) -> Color {
    notice.severity == .error ? .red : .orange
  }
}

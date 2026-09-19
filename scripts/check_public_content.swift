import Foundation

func git(_ arguments: [String]) throws -> Data {
  let process = Process()
  let pipe = Pipe()
  process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
  process.arguments = arguments
  process.standardOutput = pipe
  try process.run()
  let data = pipe.fileHandleForReading.readDataToEndOfFile()
  process.waitUntilExit()
  guard process.terminationStatus == 0 else { throw CheckError("Cannot list source files.") }
  return data
}

struct CheckError: Error, CustomStringConvertible {
  let description: String
  init(_ text: String) { description = text }
}

let rules: [(String, String)] = [
  ("private key", #"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"#),
  (
    "credential",
    #"(?:gh[pousr]_[A-Za-z0-9]{25,}|github_pat_[A-Za-z0-9_]{30,}|AKIA[0-9A-Z]{16}|sk-(?:proj-|ant-)?[A-Za-z0-9_-]{32,})"#
  ),
  (
    "personal home path",
    #"/(?:Users|home)/(?!example(?:/|\b)|sample(?:/|\b)|Shared(?:/|\b))[^\s\"'`<>]+"#
  ),
  ("computer address", #"[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+\.(?:local|lan)\b"#),
  ("personal email", #"[A-Za-z0-9._+-]+@(?:icloud|gmail|outlook|hotmail|yahoo)\.com\b"#),
  ("agent metadata", #"(?i)\b(?:codex|claude|anthropic|chatgpt|openai)\b|Co-Authored-By"#),
]

do {
  let data = try git(["ls-files", "--cached", "--others", "--exclude-standard", "-z"])
  let files = Set(data.split(separator: 0).map { String(decoding: $0, as: UTF8.self) }).sorted()
  let patterns = try rules.map { ($0.0, try NSRegularExpression(pattern: $0.1)) }
  var failures = 0
  var inspected = 0
  for file in files {
    // Removed files can still be in the index until the change is staged.
    // A broken link remains an input and must not be mistaken for a removal.
    let isLink = (try? FileManager.default.destinationOfSymbolicLink(atPath: file)) != nil
    guard isLink || FileManager.default.fileExists(atPath: file) else { continue }
    inspected += 1
    let lowercased = file.lowercased()
    let components = lowercased.split(separator: "/").map(String.init)
    let filename = components.last ?? lowercased
    if file.hasPrefix(".local/") || ["AGENTS.md", "CLAUDE.md", "TODO.md"].contains(file)
      || ["design/", "results/", "dist/", "VM/"].contains(where: file.hasPrefix)
      || components.contains(where: [".build", ".swiftpm"].contains)
      || filename == ".ds_store" || filename.hasPrefix("._")
      || [
        ".provisionprofile", ".mobileprovision", ".p12", ".pfx", ".key", ".zip", ".pkg",
        ".dmg", ".log", ".jsonl",
      ].contains(where: lowercased.hasSuffix)
    {
      print("\(file): private material is included in the public file set")
      failures += 1
      continue
    }
    let attributes = try FileManager.default.attributesOfItem(atPath: file)
    guard attributes[.type] as? FileAttributeType == .typeRegular else {
      print("\(file): public inputs must be regular files, not links or special files")
      failures += 1
      continue
    }
    guard let text = try? String(contentsOfFile: file, encoding: .utf8), !text.contains("\0") else {
      print("\(file): unexpected binary or unreadable source file; review before publication")
      failures += 1
      continue
    }
    for (index, line) in text.components(separatedBy: .newlines).enumerated() {
      for (label, expression) in patterns {
        // The checker necessarily contains the patterns it searches for.
        if file == "scripts/check_public_content.swift" { continue }
        if expression.firstMatch(in: line, range: NSRange(line.startIndex..., in: line)) != nil {
          print("\(file):\(index + 1): inspect \(label)")
          failures += 1
        }
      }
    }
  }
  guard failures == 0 else {
    throw CheckError(
      "Public source content check failed (\(failures) findings). Values are not printed.")
  }
  print(
    "Public source content check passed for \(inspected) files. Manual review is still required.")
} catch {
  FileHandle.standardError.write(Data("\(error)\n".utf8))
  exit(1)
}

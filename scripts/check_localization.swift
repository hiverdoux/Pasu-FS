import Foundation

// Compares the strings the compiler found in the app with the String Catalogs, and checks that
// the installer pages and messages exist in every language.
// Usage: swift check_localization.swift STRINGSDATA_DIRECTORY
// The directory comes from building with `-emit-localized-strings`.

struct CheckError: Error, CustomStringConvertible {
  let description: String
  init(_ text: String) { description = text }
}

let requiredLanguages = ["ko"]
let appCatalog = "Product/Localization/App/Localizable.xcstrings"
let infoPlistCatalogs = [
  "Product/Localization/App/InfoPlist.xcstrings",
  "Product/Localization/SystemExtension/InfoPlist.xcstrings",
]
let appSources = "Sources/PasuFSApp"
let installerResources = "Product/Installer/Resources"
let installerScript = "scripts/build_installer.sh"

func installerKeys(in folder: String) throws -> Set<String> {
  let path = "\(folder)/Localizable.strings"
  guard let strings = NSDictionary(contentsOfFile: path) as? [String: String] else {
    throw CheckError("\(path): not a strings file")
  }
  return Set(strings.keys)
}

/// Keys the installer script reads with system.localizedString("KEY").
func installerKeysUsed(in script: String) -> Set<String> {
  var keys = Set<String>()
  for part in script.components(separatedBy: "system.localizedString(\"").dropFirst() {
    if let end = part.firstIndex(of: "\"") {
      keys.insert(String(part[..<end]))
    }
  }
  return keys
}

func jsonObject(at path: String) throws -> [String: Any] {
  let data = try Data(contentsOf: URL(fileURLWithPath: path))
  guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
    throw CheckError("\(path): not a JSON object")
  }
  return object
}

func catalogStrings(_ path: String) throws -> [String: [String: Any]] {
  guard let strings = try jsonObject(at: path)["strings"] as? [String: [String: Any]] else {
    throw CheckError("\(path): missing strings")
  }
  return strings
}

func isTranslated(_ localization: Any?) -> Bool {
  guard let localization = localization as? [String: Any] else { return false }
  if let unit = localization["stringUnit"] as? [String: Any] {
    return unit["state"] as? String == "translated" && !(unit["value"] as? String ?? "").isEmpty
  }
  if let variations = localization["variations"] as? [String: Any] {
    return variations.values.allSatisfy { cases in
      guard let cases = cases as? [String: Any], !cases.isEmpty else { return false }
      return cases.values.allSatisfy(isTranslated)
    }
  }
  return false
}

do {
  guard CommandLine.arguments.count == 2 else {
    throw CheckError("Usage: swift check_localization.swift STRINGSDATA_DIRECTORY")
  }
  let root = FileManager.default.currentDirectoryPath
  let sourceDirectory = URL(fileURLWithPath: appSources, relativeTo: URL(fileURLWithPath: root))
    .standardizedFileURL.path
  let stringsDirectory = URL(fileURLWithPath: CommandLine.arguments[1])
  var codeKeys = Set<String>()
  var extractedFiles = Set<String>()
  for file in try FileManager.default.contentsOfDirectory(
    at: stringsDirectory, includingPropertiesForKeys: nil)
  where file.pathExtension == "stringsdata" {
    let object = try jsonObject(at: file.path)
    guard let source = object["source"] as? String,
      let tables = object["tables"] as? [String: [[String: Any]]]
    else {
      throw CheckError("\(file.lastPathComponent): unexpected stringsdata format")
    }
    let sourcePath = URL(fileURLWithPath: source).standardizedFileURL.path
    guard sourcePath.hasPrefix(sourceDirectory + "/") else { continue }
    extractedFiles.insert(URL(fileURLWithPath: sourcePath).lastPathComponent)
    for (table, entries) in tables {
      guard table == "Localizable" else {
        throw CheckError("\(sourcePath): strings must use the Localizable table, not \(table)")
      }
      for entry in entries {
        guard let key = entry["key"] as? String else {
          throw CheckError("\(file.lastPathComponent): entry without a key")
        }
        codeKeys.insert(key)
      }
    }
  }

  var problems: [String] = []
  let swiftFiles = try FileManager.default.contentsOfDirectory(atPath: sourceDirectory)
    .filter { $0.hasSuffix(".swift") }
  for file in swiftFiles.sorted() where !extractedFiles.contains(file) {
    problems.append(
      "\(appSources)/\(file): no extracted strings; rebuild with -emit-localized-strings")
  }

  let catalog = try catalogStrings(appCatalog)
  for key in codeKeys.sorted() {
    guard let entry = catalog[key] else {
      problems.append("\(appCatalog): missing key “\(key)”")
      continue
    }
    let localizations = entry["localizations"] as? [String: Any] ?? [:]
    for language in requiredLanguages where !isTranslated(localizations[language]) {
      problems.append("\(appCatalog): no \(language) translation for “\(key)”")
    }
  }
  for (key, entry) in catalog.sorted(by: { $0.key < $1.key }) where !codeKeys.contains(key) {
    if entry["extractionState"] as? String != "manual" {
      problems.append("\(appCatalog): “\(key)” is no longer used by the app")
    }
  }

  for path in infoPlistCatalogs {
    for (key, entry) in try catalogStrings(path) {
      let localizations = entry["localizations"] as? [String: Any] ?? [:]
      for language in ["en"] + requiredLanguages where !isTranslated(localizations[language]) {
        problems.append("\(path): no \(language) value for \(key)")
      }
    }
  }

  // The installer pages and messages need the same files and keys in every language.
  let englishInstaller = "\(installerResources)/en.lproj"
  let englishFiles = try Set(FileManager.default.contentsOfDirectory(atPath: englishInstaller))
  let englishKeys = try installerKeys(in: englishInstaller)
  let scriptText = try String(contentsOfFile: installerScript, encoding: .utf8)
  for key in installerKeysUsed(in: scriptText) where !englishKeys.contains(key) {
    problems.append("\(installerScript): “\(key)” is missing from \(englishInstaller)")
  }
  for language in requiredLanguages {
    let folder = "\(installerResources)/\(language).lproj"
    let files = Set((try? FileManager.default.contentsOfDirectory(atPath: folder)) ?? [])
    for file in englishFiles.subtracting(files).sorted() {
      problems.append("\(folder): missing \(file)")
    }
    let keys = files.contains("Localizable.strings") ? try installerKeys(in: folder) : []
    for key in englishKeys.subtracting(keys).sorted() {
      problems.append("\(folder)/Localizable.strings: missing “\(key)”")
    }
  }

  guard problems.isEmpty else {
    for problem in problems {
      print(problem)
    }
    throw CheckError("Localization check failed (\(problems.count) findings).")
  }
  print(
    "Localization check passed for \(codeKeys.count) app strings in \(extractedFiles.count) source files and the installer pages."
  )
} catch {
  FileHandle.standardError.write(Data("\(error)\n".utf8))
  exit(1)
}

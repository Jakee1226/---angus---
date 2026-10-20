import Foundation

// 準備本機 JSON 檔，交給 SwiftUI ShareLink 由使用者選擇分享去處。
// 此處不呼叫網路 API，也不自動傳送報告。
enum SecurityReportExporter {
    static func prepareFile(report: SecurityIRReport) throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("SecurityIRExports", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let fileURL = directory.appendingPathComponent("IR-Report-\(report.id).json")
        try report.jsonData().write(to: fileURL, options: .atomic)
        return fileURL
    }
}

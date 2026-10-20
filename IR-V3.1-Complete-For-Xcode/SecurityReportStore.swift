import Foundation

// 分析歷史與 A 的 events.json 分開保存，預設最多保留 10 份報告。
@MainActor
final class SecurityReportStore {
    private(set) var reports: [SecurityIRReport] = []
    private(set) var loadErrorMessage: String?
    private let fileURL: URL
    private let maximumCount: Int
    private var failedToLoad = false

    init(fileURL: URL? = nil, maximumCount: Int = 10) {
        let directory = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        self.fileURL = fileURL ?? directory
            .appendingPathComponent("SecurityIR", isDirectory: true)
            .appendingPathComponent("reports.json")
        self.maximumCount = max(1, maximumCount)
        guard FileManager.default.fileExists(atPath: self.fileURL.path) else { return }
        do {
            let data = try Data(contentsOf: self.fileURL)
            reports = Array(try JSONDecoder().decode([SecurityIRReport].self, from: data).prefix(self.maximumCount))
        } catch {
            failedToLoad = true
            loadErrorMessage = "歷史報告讀取失敗；舊檔已保留，本次分析仍可匯出。"
        }
    }

    func append(_ report: SecurityIRReport) throws {
        guard !failedToLoad else { throw SecurityReportStorageError.historyUnreadable }
        var next = reports.filter { $0.id != report.id }
        next.insert(report, at: 0)
        next = Array(next.prefix(maximumCount))
        try write(next)
        reports = next
    }

    func clear() throws {
        try write([])
        reports = []
        failedToLoad = false
        loadErrorMessage = nil
    }

    private func write(_ reports: [SecurityIRReport]) throws {
        try FileManager.default.createDirectory(
            at: fileURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        let data = try JSONEncoder().encode(reports)
        try data.write(to: fileURL, options: .atomic)
    }
}

enum SecurityReportStorageError: LocalizedError {
    case historyUnreadable

    var errorDescription: String? {
        "歷史報告無法讀取，已保留舊檔；可先匯出本次報告，或手動清除歷史後重新保存。"
    }
}

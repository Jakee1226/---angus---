import Foundation

enum TestFileService {//專門處理測試檔案工具箱
    static let defaultFileName = "test_private_file.txt"

    static var directory: URL {//找到這個 App 自己的 Application Support 資料夾
        FileManager.default.urls(for: .applicationSupportDirectory,
                                 in: .userDomainMask)[0]
    }

    static func fileURL(named name: String) -> URL {
        directory.appendingPathComponent(name)
    }

    // 準備測試檔案
    static func prepare() {
        try? FileManager.default.createDirectory(at: directory,
                                                 withIntermediateDirectories: true)//如果 Application Support 資料夾不存在，就建立它
        let url = fileURL(named: defaultFileName)
        if !FileManager.default.fileExists(atPath: url.path) {
            try? "secret test content".write(to: url, atomically: true, encoding: .utf8)
        }
    }

    // MARK: - 多檔案讀取測試情境（新增；不影響上面的單一檔案功能）

    /// 測試情境用的 5 個檔案：test_batch_01.txt ~ test_batch_05.txt
    static let batchFileNames: [String] = (1...5).map { String(format: "test_batch_%02d.txt", $0) }

    /// 刻意「不建立」的檔案，用來產生一筆真實的讀取失敗事件
    static let missingBatchFileName = "test_batch_missing.txt"

    /// 情境讀取順序：5 個存在的檔案，最後 1 個不存在的檔案
    static var batchScenarioFileNames: [String] { batchFileNames + [missingBatchFileName] }

    /// 準備多個測試檔案；已存在的不會覆蓋。不會建立 missingBatchFileName。
    static func prepareBatchFiles() {
        try? FileManager.default.createDirectory(at: directory,
                                                 withIntermediateDirectories: true)
        for (index, name) in batchFileNames.enumerated() {
            let url = fileURL(named: name)
            if !FileManager.default.fileExists(atPath: url.path) {
                try? "batch test content \(index + 1)".write(to: url, atomically: true, encoding: .utf8)
            }
        }
    }

    // 讀檔：成功回傳內容，失敗丟出錯誤
    static func read(named name: String) throws -> String {
        try String(contentsOf: fileURL(named: name), encoding: .utf8)
    }

    // MARK: - V3.2：create / write / delete（新增；上面的 read 與多檔案功能完全不變）
    // 這一層只「真的執行檔案操作」，不產生事件。事件由 EventCollector 在操作之後記錄，
    // 所以 App 內的檔案操作請一律透過 EventCollector 呼叫，才會有事件紀錄。

    /// 專用測試資料夾，位於 App 自己沙盒的 Application Support 底下。
    static let sandboxFolderName = "ATestSandbox"

    static var sandboxDirectory: URL {
        directory.appendingPathComponent(sandboxFolderName, isDirectory: true)
    }

    enum FileOperationError: LocalizedError {
        case invalidName
        case alreadyExists
        case notFound

        var errorDescription: String? {
            switch self {
            case .invalidName: return "檔名不合法（只允許英數字、底線、連字號與點，副檔名須為 .txt，最多 64 字元）。"
            case .alreadyExists: return "檔案已存在，不覆蓋。"
            case .notFound: return "檔案不存在。"
            }
        }
    }

    /// 檔名白名單：避免路徑穿越（不能含 / 或 ..），並限制只能是 .txt。
    static func isValidSandboxFileName(_ name: String) -> Bool {
        guard !name.isEmpty, name.count <= 64,
              !name.hasPrefix("."), !name.contains(".."),
              name.hasSuffix(".txt") else { return false }
        let allowed = CharacterSet(
            charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-."
        )
        return name.unicodeScalars.allSatisfy { allowed.contains($0) }
    }

    /// 取得測試資料夾內的檔案位置；檔名不合法，或最終位置不在測試資料夾內，就丟錯誤。
    static func sandboxFileURL(named name: String) throws -> URL {
        guard isValidSandboxFileName(name) else { throw FileOperationError.invalidName }
        let url = sandboxDirectory.appendingPathComponent(name)
        // 第二道檢查：就算白名單有漏洞，也確認檔案的上一層真的是測試資料夾。
        guard url.standardizedFileURL.deletingLastPathComponent().path
                == sandboxDirectory.standardizedFileURL.path else {
            throw FileOperationError.invalidName
        }
        return url
    }

    /// create：建立新檔。檔案已存在會失敗（不覆蓋）。
    static func createFile(named name: String, content: String) throws {
        let url = try sandboxFileURL(named: name)
        try FileManager.default.createDirectory(at: sandboxDirectory,
                                                withIntermediateDirectories: true)
        guard !FileManager.default.fileExists(atPath: url.path) else {
            throw FileOperationError.alreadyExists
        }
        try Data(content.utf8).write(to: url, options: [.withoutOverwriting])
    }

    /// write：寫入既有檔案（取代內容）。檔案不存在會失敗，不會順便建立。
    static func writeFile(named name: String, content: String) throws {
        let url = try sandboxFileURL(named: name)
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw FileOperationError.notFound
        }
        try content.write(to: url, atomically: true, encoding: .utf8)
    }

    /// delete：刪除既有檔案。檔案不存在會失敗。
    static func deleteFile(named name: String) throws {
        let url = try sandboxFileURL(named: name)
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw FileOperationError.notFound
        }
        try FileManager.default.removeItem(at: url)
    }

    #if DEBUG
    /// 只給 DEBUG 測試用：清空測試資料夾，讓測試可以重複執行。不會產生事件。
    static func resetSandboxForTesting() {
        try? FileManager.default.removeItem(at: sandboxDirectory)
    }
    #endif
}
import Foundation

// 【待與 A 最新 Git 檔比對】依已知 events.json / Application Support / 最近50筆介面重建。
// 注意：此為相容候選實作，不是 A 原始碼的逐字拷貝。
final class EventStore {
    private(set) var events: [SecurityEvent] = []
    private let fileURL: URL
    private let maxCount: Int
    private var lastSequence = 0

    init(fileURL: URL? = nil, maxCount: Int = 50) {
        let directory = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        self.fileURL = fileURL ?? directory.appendingPathComponent("events.json")
        self.maxCount = max(1, maxCount)
        load()
    }

    func append(_ event: SecurityEvent) {
        events.append(event)
        events = Array(events.suffix(maxCount))
        let suffix = event.eventID.drop(while: { !$0.isNumber })
        if let number = Int(suffix) { lastSequence = max(lastSequence, number) }
        save()
    }

    /// V3.2 新增：和 append 做一樣的事，但會回報寫入 events.json 是否成功。
    /// 寫檔失敗會丟出錯誤；事件仍留在記憶體（和 append 的行為一致），
    /// 呼叫端應把它當成「記錄失敗」處理。原本的 append 完全沒有改動。
    func appendChecked(_ event: SecurityEvent) throws {
        events.append(event)
        events = Array(events.suffix(maxCount))
        let suffix = event.eventID.drop(while: { !$0.isNumber })
        if let number = Int(suffix) { lastSequence = max(lastSequence, number) }
        try saveChecked()
    }

    func nextEventID() -> String {
        lastSequence += 1
        return String(format: "E%03d", lastSequence)
    }

    func recentEvents(limit: Int) -> [SecurityEvent] {
        Array(events.suffix(max(0, limit)))
    }

    func events(from start: Date?, to end: Date?) -> [SecurityEvent] {
        let parser = ISO8601DateFormatter()
        parser.formatOptions = [.withInternetDateTime]
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return events.filter {
            guard let date = fractional.date(from: $0.timestamp) ?? parser.date(from: $0.timestamp) else { return false }
            if let start, date < start { return false }
            if let end, date > end { return false }
            return true
        }
    }

    func clear() {
        events.removeAll()
        // 保留目前 session 的 ID 序列，避免清除後立刻重用；重啟後仍可能重用，P1 改進。
        save()
    }

    private func load() {
        guard let data = try? Data(contentsOf: fileURL),
              let decoded = try? JSONDecoder().decode([SecurityEvent].self, from: data) else { return }
        events = Array(decoded.suffix(maxCount))
        lastSequence = events.compactMap {
            Int($0.eventID.drop(while: { !$0.isNumber }))
        }.max() ?? 0
    }

    private func save() {
        do {
            try FileManager.default.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
            let data = try JSONEncoder().encode(events)
            try data.write(to: fileURL, options: .atomic)
        } catch {
            // 保留現有 A 介面；P1 應改成 throws 並由 UI 顯示儲存失敗。
            NSLog("EventStore save failed: %@", String(describing: error))
        }
    }

    // V3.2 新增：和 save() 寫入方式相同，但失敗時丟出錯誤，不吞掉。
    private func saveChecked() throws {
        try FileManager.default.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        let data = try JSONEncoder().encode(events)
        try data.write(to: fileURL, options: .atomic)
    }
}

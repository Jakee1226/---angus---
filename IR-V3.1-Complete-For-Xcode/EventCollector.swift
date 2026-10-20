import Foundation
import Combine

/// V3.2 新增：一次檔案操作的完整結果，讓呼叫端分得清「操作」和「記錄」各自成功與否。
struct FileOperationReport {
    let event: SecurityEvent
    let operationError: String?   // nil 代表檔案操作成功
    let recordingError: String?   // nil 代表事件已成功存檔

    var operationSucceeded: Bool { operationError == nil }
    var recordedSuccessfully: Bool { recordingError == nil }
}

// 【待與 A 最新 Git 檔比對】按先前公開介面重建；非 A 原始碼逐字拷貝。
@MainActor
final class EventCollector: ObservableObject {
    @Published private(set) var storedCount: Int = 0
    private let store: EventStore
    var events: [SecurityEvent] { store.events }

    init(store: EventStore = EventStore()) {
        self.store = store
        storedCount = store.events.count
    }

    func readFile(named fileName: String, target: String) {
        let result: String
        do {
            _ = try TestFileService.read(named: fileName)
            result = "allowed"
        } catch {
            result = "failed"
        }
        let event = SecurityEvent(
            eventID: store.nextEventID(), timestamp: SecurityEvent.nowTimestamp(),
            source: "TestApp", action: "read", target: target,
            result: result, isSimulated: false
        )
        store.append(event)
        storedCount = store.events.count
    }

    func readFiles(named fileNames: [String]) {
        for name in fileNames { readFile(named: name, target: name) }
    }

    // MARK: - V3.2：create / write / delete（新增；read 與 readFiles 完全不變）
    // 流程：真的執行檔案操作 → 依實際結果產生一筆事件 → 存檔 → 回報給呼叫端。
    // 事件只在這個函式裡產生一次，所以同一次操作不會重複記錄。
    // 這是「App 自己發起的操作」的記錄，不是對 iOS 系統或其他 App 的監控。

    @discardableResult
    func createFile(named name: String, content: String = "A module test content") -> FileOperationReport {
        performAndRecord(action: "create", fileName: name) {
            try TestFileService.createFile(named: name, content: content)
        }
    }

    @discardableResult
    func writeFile(named name: String, content: String) -> FileOperationReport {
        performAndRecord(action: "write", fileName: name) {
            try TestFileService.writeFile(named: name, content: content)
        }
    }

    @discardableResult
    func deleteFile(named name: String) -> FileOperationReport {
        performAndRecord(action: "delete", fileName: name) {
            try TestFileService.deleteFile(named: name)
        }
    }

    private func performAndRecord(
        action: String, fileName: String, operation: () throws -> Void
    ) -> FileOperationReport {
        // 1. 真的執行檔案操作，成功或失敗都要記錄。
        var operationError: String?
        do { try operation() } catch { operationError = error.localizedDescription }

        // 2. 依實際結果產生事件。target 加上資料夾前綴，避免和 read 的檔名混淆。
        //    isSimulated 為 true：這些是測試情境產生的事件，不是真實外部資安事件。
        let event = SecurityEvent(
            eventID: store.nextEventID(), timestamp: SecurityEvent.nowTimestamp(),
            source: "TestApp", action: action,
            target: "\(TestFileService.sandboxFolderName)/\(String(fileName.prefix(100)))",
            result: operationError == nil ? "allowed" : "failed",
            isSimulated: true
        )

        // 3. 存檔；存檔失敗不能被吞掉，要回報給呼叫端。
        var recordingError: String?
        do { try store.appendChecked(event) } catch {
            recordingError = error.localizedDescription
            NSLog("EventCollector: 事件存檔失敗 %@", String(describing: error))
        }
        storedCount = store.events.count

        return FileOperationReport(event: event, operationError: operationError,
                                   recordingError: recordingError)
    }

    func recentEvents(limit: Int) -> [SecurityEvent] { store.recentEvents(limit: limit) }
    func events(from start: Date?, to end: Date?) -> [SecurityEvent] { store.events(from: start, to: end) }

    func printStoredEvents() {
        #if DEBUG
        for event in store.events { print(event.jsonString()) }
        #endif
    }

    func clearEvents() {
        store.clear()
        storedCount = store.events.count
    }
}

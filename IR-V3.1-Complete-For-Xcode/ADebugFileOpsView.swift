import SwiftUI

#if DEBUG
// V3.2 A 模組 DEBUG 測試畫面（獨立檔案，不修改 B 的 ContentView；Release 版本不會編進去）。
//
// 整合方式：在 ContentView 的 NavigationStack 內，用「同一個」collector 開啟這個畫面：
//
//     #if DEBUG
//     NavigationLink("A 模組檔案操作測試") { ADebugFileOpsView(collector: collector) }
//     #endif
//
// 注意：一定要傳入 ContentView 已經有的 collector，不要在這裡另外建立 EventCollector。
// 否則會有兩份 EventStore 同時寫 events.json，事件會互相覆蓋。
//
// 這些按鈕只呼叫 collector.createFile / writeFile / deleteFile。事件是 collector 在操作後
// 自動記錄的，沒有「另外記錄」的按鈕。這是 App 自己發起的測試操作，不是系統級監控。
@MainActor
struct ADebugFileOpsView: View {
    @ObservedObject var collector: EventCollector
    @State private var lastResult = "尚未執行"
    @State private var checklist: [String] = []

    private let testFile = "a_test_1.txt"
    private let missingFile = "a_missing.txt"

    var body: some View {
        List {
            Section("說明") {
                Text("所有操作只發生在 App 沙盒的 ATestSandbox 資料夾，新增的事件都標記為模擬事件（is_simulated = true）。")
                    .font(.caption)
                Text("目前事件數：\(collector.storedCount)（上限 50 筆）")
                    .font(.caption)
            }

            Section("單項測試") {
                Button("重設測試資料夾（不產生事件）") {
                    TestFileService.resetSandboxForTesting()
                    lastResult = "測試資料夾已清空"
                    checklist = []
                }
                Button("T1 create a_test_1.txt → 預期 allowed") {
                    show(collector.createFile(named: testFile))
                }
                Button("T2 再 create 同一個檔 → 預期 failed") {
                    show(collector.createFile(named: testFile))
                }
                Button("T3 write a_test_1.txt → 預期 allowed") {
                    show(collector.writeFile(named: testFile, content: "updated content"))
                }
                Button("T4 write 不存在的檔 → 預期 failed") {
                    show(collector.writeFile(named: missingFile, content: "x"))
                }
                Button("T5 delete a_test_1.txt → 預期 allowed") {
                    show(collector.deleteFile(named: testFile))
                }
                Button("T6 delete 不存在的檔 → 預期 failed") {
                    show(collector.deleteFile(named: missingFile))
                }
                Button("路徑穿越 create ../escape.txt → 預期 failed") {
                    show(collector.createFile(named: "../escape.txt"))
                }
            }

            Section("一鍵依序執行") {
                Button("重設後依序執行 T1～T6 與路徑穿越測試") { runAll() }
            }

            Section("最近一次結果") {
                Text(lastResult).font(.caption)
                ForEach(checklist, id: \.self) { line in
                    Text(line).font(.caption)
                }
            }
        }
        .navigationTitle("A 檔案操作測試")
    }

    private func show(_ report: FileOperationReport) {
        lastResult = describe(report)
    }

    private func describe(_ report: FileOperationReport) -> String {
        let event = report.event
        var text = "\(event.eventID)｜\(event.action)｜\(event.result)｜\(event.target)"
        if let error = report.operationError { text += "｜操作錯誤：\(error)" }
        if report.recordedSuccessfully {
            text += "｜事件已存檔"
        } else {
            text += "｜⚠️ 事件存檔失敗：\(report.recordingError ?? "未知原因")"
        }
        return text
    }

    private func runAll() {
        TestFileService.resetSandboxForTesting()
        let cases: [(label: String, expected: String, report: FileOperationReport)] = [
            ("T1 create", "allowed", collector.createFile(named: testFile)),
            ("T2 create 已存在", "failed", collector.createFile(named: testFile)),
            ("T3 write", "allowed", collector.writeFile(named: testFile, content: "updated content")),
            ("T4 write 不存在", "failed", collector.writeFile(named: missingFile, content: "x")),
            ("T5 delete", "allowed", collector.deleteFile(named: testFile)),
            ("T6 delete 不存在", "failed", collector.deleteFile(named: missingFile)),
            ("路徑穿越 create", "failed", collector.createFile(named: "../escape.txt"))
        ]
        var lines = cases.map { item -> String in
            let passed = item.report.event.result == item.expected && item.report.recordedSuccessfully
            return "\(passed ? "✅" : "❌") \(item.label)：\(item.report.event.action) / \(item.report.event.result)（預期 \(item.expected)）"
        }
        // 確認沒有任何檔案跑到測試資料夾之外。
        let escaped = FileManager.default.fileExists(
            atPath: TestFileService.directory.appendingPathComponent("escape.txt").path)
        lines.append(escaped ? "❌ 沙盒外出現 escape.txt" : "✅ 沙盒外沒有出現 escape.txt")
        checklist = lines
        lastResult = "已執行 \(cases.count) 項，請看下方結果"
    }
}
#endif
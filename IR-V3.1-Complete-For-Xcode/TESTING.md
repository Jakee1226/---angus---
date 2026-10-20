# TESTING — V3.1

## 已實際執行

- Linux Swift 6 工具鏈對 `SecurityEvent.swift`、`SecurityAnalyzer.swift`、`SecurityAIModels.swift`、`TestFileService.swift`、`SecurityReportStore.swift`、`SecurityReportExporter.swift` 六檔執行 `swiftc -typecheck`，成功。這不是 iOS App Build。

## B 尚需測試

1. Xcode Product → Build，確認新舊檔沒有重複定義，Foundation Models API 正確。
2. 對 App Target 的實際 module 名稱修正 XCTest import，Product → Test。
3. 首次啟動建立敏感測試檔；讀一次成功、讀不存在檔一次失敗、五個檔成功讀取及一個失敗，查看事件列表。
4. 10 次敏感讀取不觸發，11 次觸發；5 不同檔成功讀取觸發；5 次失敗讀取觸發。
5. 檢查無效時間跳過計數；三條規則同來源顯示 3 警示／1 來源。
6. 重複「開始 AI → 停止等待」同一請求不產生重複報告。
7. 匯出 JSON、分享選擇、ReportStore 10 份上限，舊報告解碼失敗時是否保留原始檔。
8. Release 設定不應顯示事件 JSON Console 按鈕。
9. 模型不可用時固定規則說明；模型可用時於合格實機檢查生成輸出。

**不可宣稱以上 Xcode／實機步驟已通過。**

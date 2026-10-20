import Foundation

// C 模組 v3-P0：資料契約（修改自 v2；檔名請以專案實際為準）。模型只取得數字統計與來源代號，不取得檔案內容。
// 原本 SecurityEvent、SecurityAnalyzer 的格式與門檻保持不變。

struct SecuritySourceAlias: Codable, Equatable, Sendable, Identifiable {
    let alias: String
    let source: String
    var id: String { alias }
}

// MARK: - V3：規則代號與說明資料（新增）

enum SecurityRuleID {
    static let sensitiveReadBurst = "sensitive_read_burst"
    static let multiFileRead = "multi_file_read"
    static let repeatedReadFailure = "repeated_read_failure"
    // 只用於解碼 v2 舊報告：舊格式沒有保存規則代號，不猜測。
    static let legacyUnknown = "legacy_unknown"
}

enum SecurityRuleInfo {
    static func displayName(for ruleID: String) -> String {
        switch ruleID {
        case SecurityRuleID.sensitiveReadBurst: return "敏感資料大量讀取"
        case SecurityRuleID.multiFileRead: return "多檔案異常讀取"
        case SecurityRuleID.repeatedReadFailure: return "短時間大量讀取失敗"
        default: return "其他規則"
        }
    }

    // 給 AI Context 用：說明 count 在這條規則代表什麼。
    static func countUnit(for ruleID: String) -> String {
        switch ruleID {
        case SecurityRuleID.sensitiveReadBurst: return "successful_sensitive_reads"
        case SecurityRuleID.multiFileRead: return "distinct_targets"
        case SecurityRuleID.repeatedReadFailure: return "failed_reads"
        default: return "unknown"
        }
    }

    // 給畫面用的單位文字。
    static func countUnitLabel(for ruleID: String) -> String {
        switch ruleID {
        case SecurityRuleID.sensitiveReadBurst: return "次成功讀取"
        case SecurityRuleID.multiFileRead: return "個不同檔案"
        case SecurityRuleID.repeatedReadFailure: return "次失敗讀取"
        default: return ""
        }
    }

    // 單筆事件「可能被哪些規則計入」。是否真的觸發，取決於同來源整批事件。
    static func participatingRuleIDs(for event: SecurityEvent) -> [String] {
        guard event.action == "read" else { return [] }
        if event.result == "failed" { return [SecurityRuleID.repeatedReadFailure] }
        guard event.result == "allowed" else { return [] }
        var ids = [SecurityRuleID.multiFileRead]
        if SecurityAnalyzer.shouldCount(event) {
            ids.insert(SecurityRuleID.sensitiveReadBurst, at: 0)
        }
        return ids
    }
}

extension SecurityAnalysisResult {
    // 不重複的觸發來源數；與 findings.count（警示筆數）是不同概念。
    var distinctSourceCount: Int { Set(findings.map { $0.source }).count }
}

struct SecurityAIRuleSetting: Codable, Equatable, Sendable {
    let ruleID: String
    let windowSeconds: Int
    let threshold: Int
    let comparison: String   // ">" 或 ">="
    let countUnit: String
}

// v3：每筆 Fact 帶規則代號與 count 的單位。舊報告（只有 peakReadCount）可解碼。
struct SecurityAIFindingFact: Codable, Equatable, Sendable {
    let sourceAlias: String
    let ruleID: String
    let count: Int
    let risk: String
    let countUnit: String

    init(sourceAlias: String, ruleID: String, count: Int, risk: String, countUnit: String) {
        self.sourceAlias = sourceAlias
        self.ruleID = ruleID
        self.count = count
        self.risk = risk
        self.countUnit = countUnit
    }

    private enum CodingKeys: String, CodingKey {
        case sourceAlias, ruleID, count, risk, countUnit
    }
    private enum LegacyKeys: String, CodingKey {
        case peakReadCount
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        sourceAlias = try c.decode(String.self, forKey: .sourceAlias)
        if let rule = try c.decodeIfPresent(String.self, forKey: .ruleID) {
            ruleID = rule
            count = try c.decode(Int.self, forKey: .count)
            risk = try c.decodeIfPresent(String.self, forKey: .risk) ?? "unknown"
            countUnit = try c.decodeIfPresent(String.self, forKey: .countUnit)
                ?? SecurityRuleInfo.countUnit(for: rule)
        } else {
            let legacy = try decoder.container(keyedBy: LegacyKeys.self)
            ruleID = SecurityRuleID.legacyUnknown
            count = try legacy.decode(Int.self, forKey: .peakReadCount)
            risk = "unknown"
            countUnit = "unknown"
        }
    }
}

struct SecurityAIContext: Codable, Equatable, Sendable {
    static let maximumFindingDetails = 8

    let totalEvents: Int
    let eligibleReads: Int          // 符合敏感讀取計數條件的成功讀取（沿用 v2 語義）
    let allowedReads: Int           // v3 新增：所有成功讀取。v2 舊報告解碼時為 0（當時未記錄）
    let failedReads: Int
    let excludedEvents: Int         // 沿用 v2 算法：總數 − eligibleReads − failedReads
    let simulatedEvents: Int
    // 以下三個是 v2 欄位，描述第一條規則（sensitive_read_burst），保留以維持相容。
    let windowSeconds: Int
    let threshold: Int
    let comparison: String
    // v3：三條規則各自的門檻。v2 舊報告解碼時為空陣列。
    let ruleSettings: [SecurityAIRuleSetting]
    let triggeredSourceCount: Int   // 不重複來源數（v3 起的正確語義）
    let triggeredFindingCount: Int  // 警示（Finding）總筆數
    let triggeredRuleIDs: [String]  // 實際觸發的規則代號（不重複、排序）
    let omittedFindingCount: Int
    let findingFacts: [SecurityAIFindingFact]

    init(totalEvents: Int, eligibleReads: Int, allowedReads: Int, failedReads: Int,
         excludedEvents: Int, simulatedEvents: Int, windowSeconds: Int, threshold: Int,
         comparison: String, ruleSettings: [SecurityAIRuleSetting],
         triggeredSourceCount: Int, triggeredFindingCount: Int, triggeredRuleIDs: [String],
         omittedFindingCount: Int, findingFacts: [SecurityAIFindingFact]) {
        self.totalEvents = totalEvents
        self.eligibleReads = eligibleReads
        self.allowedReads = allowedReads
        self.failedReads = failedReads
        self.excludedEvents = excludedEvents
        self.simulatedEvents = simulatedEvents
        self.windowSeconds = windowSeconds
        self.threshold = threshold
        self.comparison = comparison
        self.ruleSettings = ruleSettings
        self.triggeredSourceCount = triggeredSourceCount
        self.triggeredFindingCount = triggeredFindingCount
        self.triggeredRuleIDs = triggeredRuleIDs
        self.omittedFindingCount = omittedFindingCount
        self.findingFacts = findingFacts
    }

    private enum CodingKeys: String, CodingKey {
        case totalEvents, eligibleReads, allowedReads, failedReads, excludedEvents
        case simulatedEvents, windowSeconds, threshold, comparison, ruleSettings
        case triggeredSourceCount, triggeredFindingCount, triggeredRuleIDs
        case omittedFindingCount, findingFacts
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        totalEvents = try c.decode(Int.self, forKey: .totalEvents)
        eligibleReads = try c.decode(Int.self, forKey: .eligibleReads)
        allowedReads = try c.decodeIfPresent(Int.self, forKey: .allowedReads) ?? 0
        failedReads = try c.decode(Int.self, forKey: .failedReads)
        excludedEvents = try c.decode(Int.self, forKey: .excludedEvents)
        simulatedEvents = try c.decode(Int.self, forKey: .simulatedEvents)
        windowSeconds = try c.decode(Int.self, forKey: .windowSeconds)
        threshold = try c.decode(Int.self, forKey: .threshold)
        comparison = try c.decode(String.self, forKey: .comparison)
        ruleSettings = try c.decodeIfPresent([SecurityAIRuleSetting].self, forKey: .ruleSettings) ?? []
        omittedFindingCount = try c.decode(Int.self, forKey: .omittedFindingCount)
        let facts = try c.decode([SecurityAIFindingFact].self, forKey: .findingFacts)
        findingFacts = facts
        let storedCount = try c.decode(Int.self, forKey: .triggeredSourceCount)
        if let findings = try c.decodeIfPresent(Int.self, forKey: .triggeredFindingCount) {
            triggeredFindingCount = findings
            triggeredSourceCount = storedCount
        } else {
            // v2 的 triggeredSourceCount 其實是 findings.count，這裡更正語義。
            // 來源數只能由保存下來的 facts 推算（若有省略，可能偏少；完整資料以 ruleResult 為準）。
            triggeredFindingCount = storedCount
            triggeredSourceCount = Set(facts.map { $0.sourceAlias }).count
        }
        triggeredRuleIDs = try c.decodeIfPresent([String].self, forKey: .triggeredRuleIDs)
            ?? Array(Set(facts.map { $0.ruleID })).sorted()
    }

    static func make(events: [SecurityEvent], result: SecurityAnalysisResult) -> SecurityAIContext {
        let eligible = events.filter { SecurityAnalyzer.shouldCount($0) }.count
        let allowed = events.filter { $0.action == "read" && $0.result == "allowed" }.count
        let failed = events.filter { $0.action == "read" && $0.result == "failed" }.count
        let aliases = sourceAliases(for: events)
        let lookup = Dictionary(uniqueKeysWithValues: aliases.map { ($0.source, $0.alias) })
        let selected = result.findings.prefix(maximumFindingDetails)
        let facts = selected.map { finding in
            SecurityAIFindingFact(
                sourceAlias: lookup[finding.source] ?? "UNKNOWN",
                ruleID: finding.ruleID,
                count: finding.count,
                risk: String(describing: finding.risk),
                countUnit: SecurityRuleInfo.countUnit(for: finding.ruleID)
            )
        }
        return SecurityAIContext(
            totalEvents: events.count,
            eligibleReads: eligible,
            allowedReads: allowed,
            failedReads: failed,
            excludedEvents: events.count - eligible - failed,
            simulatedEvents: events.filter { $0.isSimulated }.count,
            windowSeconds: result.rule.windowSeconds,
            threshold: result.rule.threshold,
            comparison: result.rule.comparison,
            ruleSettings: currentRuleSettings(),
            triggeredSourceCount: result.distinctSourceCount,
            triggeredFindingCount: result.findings.count,
            triggeredRuleIDs: Array(Set(result.findings.map { $0.ruleID })).sorted(),
            omittedFindingCount: max(0, result.findings.count - facts.count),
            findingFacts: facts
        )
    }

    // 門檻直接取自 SecurityAnalyzer 常數，避免 UI／說明／分析器三處各寫一份而不一致。
    static func currentRuleSettings() -> [SecurityAIRuleSetting] {
        [
            SecurityAIRuleSetting(ruleID: SecurityRuleID.sensitiveReadBurst,
                                  windowSeconds: SecurityAnalyzer.windowSeconds,
                                  threshold: SecurityAnalyzer.threshold, comparison: ">",
                                  countUnit: SecurityRuleInfo.countUnit(for: SecurityRuleID.sensitiveReadBurst)),
            SecurityAIRuleSetting(ruleID: SecurityRuleID.multiFileRead,
                                  windowSeconds: SecurityAnalyzer.windowSeconds,
                                  threshold: SecurityAnalyzer.multiFileThreshold, comparison: ">=",
                                  countUnit: SecurityRuleInfo.countUnit(for: SecurityRuleID.multiFileRead)),
            SecurityAIRuleSetting(ruleID: SecurityRuleID.repeatedReadFailure,
                                  windowSeconds: SecurityAnalyzer.windowSeconds,
                                  threshold: SecurityAnalyzer.failedReadThreshold, comparison: ">=",
                                  countUnit: SecurityRuleInfo.countUnit(for: SecurityRuleID.repeatedReadFailure))
        ]
    }

    // 原始 source 只用在畫面與本機報告，不會放進 AI prompt。
    static func sourceAliases(for events: [SecurityEvent]) -> [SecuritySourceAlias] {
        Set(events.map { $0.source }).sorted().enumerated().map { index, source in
            SecuritySourceAlias(alias: String(format: "S%02d", index + 1), source: source)
        }
    }

    func jsonString() throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return String(decoding: try encoder.encode(self), as: UTF8.self)
    }
}

enum SecurityExplanationOrigin: String, Codable, Sendable {
    case onDeviceAI = "on_device_ai"
    case ruleFallback = "rule_fallback"

    var displayName: String {
        switch self {
        case .onDeviceAI: return "本地 AI 說明"
        case .ruleFallback: return "固定規則說明"
        }
    }
}

struct SecurityExplanation: Codable, Equatable, Sendable {
    let origin: SecurityExplanationOrigin
    let summary: String
    let whyItMatters: String
    let recommendedNextStep: String
    let limits: String

    // 引導生成保證資料結構；這裡另外排除空白輸出，並控制畫面長度。
    // 這不是對模型內容真實性的驗證，規則結果仍是獨立欄位。
    func validated() throws -> SecurityExplanation {
        func field(_ value: String) throws -> String {
            let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { throw SecurityAIError.invalidResponse }
            if trimmed.count > 320 {
                return String(trimmed.prefix(320)) + "…"
            }
            return trimmed
        }
        return try SecurityExplanation(
            origin: origin,
            summary: field(summary),
            whyItMatters: field(whyItMatters),
            recommendedNextStep: field(recommendedNextStep),
            limits: field(limits)
        )
    }
}

struct SecurityAIAvailability: Equatable, Sendable {
    let isAvailable: Bool
    let message: String
}

enum SecurityAIError: LocalizedError {
    case unavailable(String)
    case invalidResponse
    case generationFailed

    var errorDescription: String? {
        switch self {
        case let .unavailable(message): return message
        case .invalidResponse: return "模型輸出不完整，已改用固定規則說明。"
        case .generationFailed: return "本地模型此次未能完成說明，已保留規則結果。"
        }
    }
}

enum SecurityRuleExplanation {
    static func make(context: SecurityAIContext) -> SecurityExplanation {
        let summary: String
        let meaning: String
        let nextStep: String

        if context.totalEvents == 0 {
            summary = "目前沒有可分析的事件。"
            meaning = "沒有資料可供規則判斷。"
            nextStep = "先產生或收集事件，再執行分析。"
        } else if context.triggeredFindingCount == 0 {
            summary = "這批 \(context.totalEvents) 筆事件沒有達到任何規則的設定門檻。"
            meaning = "目前檢查三種行為：敏感測試檔大量讀取、多檔案讀取、連續讀取失敗；沒有來源在任意 \(context.windowSeconds) 秒內達到門檻。"
            nextStep = "保留事件紀錄；若操作行為改變，再對更新後的事件進行分析。"
        } else {
            let ruleIDs = context.triggeredRuleIDs
            if ruleIDs.count == 1, let only = ruleIDs.first {
                summary = "有 \(context.triggeredSourceCount) 個來源觸發「\(SecurityRuleInfo.displayName(for: only))」規則（共 \(context.triggeredFindingCount) 筆警示）。"
                meaning = ruleSentence(only, context: context) + "，需要確認是否符合預期。"
            } else {
                summary = "這批事件有 \(context.triggeredSourceCount) 個來源、共 \(context.triggeredFindingCount) 筆警示，涉及 \(ruleIDs.count) 條規則。"
                meaning = ruleIDs.map { ruleSentence($0, context: context) }.joined(separator: "；") + "。這些都需要確認是否符合預期。"
            }
            nextStep = nextStepText(ruleIDs: ruleIDs)
        }

        let simulatedNote = context.simulatedEvents > 0
            ? "這批有 \(context.simulatedEvents) 筆模擬事件，相關警示只代表測試情境，不能當成已確認的真實攻擊。"
            : "這批沒有標記為模擬的事件，但警示仍不等於已確認攻擊。"
        return SecurityExplanation(
            origin: .ruleFallback,
            summary: summary,
            whyItMatters: meaning,
            recommendedNextStep: nextStep,
            limits: "只分析 App 提供且仍保留的事件，並非整支手機的監控。\(simulatedNote)未觸發也不等於全面安全。"
        )
    }

    private static func ruleSentence(_ ruleID: String, context: SecurityAIContext) -> String {
        let setting = context.ruleSettings.first { $0.ruleID == ruleID }
        let window = setting?.windowSeconds ?? context.windowSeconds
        switch ruleID {
        case SecurityRuleID.sensitiveReadBurst:
            if let s = setting {
                return "同一來源在 \(window) 秒內成功讀取指定的敏感測試檔\(s.comparison == ">" ? "超過" : "至少") \(s.threshold) 次"
            }
            return "同一來源短時間內大量成功讀取指定的敏感測試檔"
        case SecurityRuleID.multiFileRead:
            if let s = setting {
                return "同一來源在 \(window) 秒內成功讀取至少 \(s.threshold) 個不同檔案"
            }
            return "同一來源短時間內讀取多個不同檔案"
        case SecurityRuleID.repeatedReadFailure:
            if let s = setting {
                return "同一來源在 \(window) 秒內讀取失敗至少 \(s.threshold) 次"
            }
            return "同一來源短時間內發生大量讀取失敗"
        default:
            return "有未能辨識的規則被觸發，請查看規則結果"
        }
    }

    private static func nextStepText(ruleIDs: [String]) -> String {
        var parts: [String] = ["先核對是否為測試或使用者預期操作，並查看規則結果列出的來源、數量與時間範圍。"]
        if ruleIDs.contains(SecurityRuleID.multiFileRead) {
            parts.append("多檔案讀取：確認該來源是否本來就需要一次處理多個檔案。")
        }
        if ruleIDs.contains(SecurityRuleID.repeatedReadFailure) {
            parts.append("讀取失敗：確認是檔案不存在、權限不足，或是程式在重複嘗試。")
        }
        parts.append("需要時保存本次報告。")
        return parts.joined()
    }
}

struct SecurityIRReport: Codable, Identifiable {
    let id: String
    let schemaVersion: String
    let moduleVersion: String
    let generatedAt: String
    let scope: String
    let ruleResult: SecurityAnalysisResult
    let context: SecurityAIContext
    let sourceAliases: [SecuritySourceAlias]
    let explanation: SecurityExplanation
    let explanationNotice: String?
    let events: [SecurityEvent]
    let notes: [String]

    static func make(
        events: [SecurityEvent],
        ruleResult: SecurityAnalysisResult,
        context: SecurityAIContext,
        explanation: SecurityExplanation,
        notice: String?
    ) -> SecurityIRReport {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return SecurityIRReport(
            id: UUID().uuidString,
            schemaVersion: "1.1",
            moduleVersion: "3.0.0-p0",
            generatedAt: formatter.string(from: Date()),
            scope: "app_generated_events",
            ruleResult: ruleResult,
            context: context,
            sourceAliases: SecurityAIContext.sourceAliases(for: events),
            explanation: explanation,
            explanationNotice: notice,
            events: events,
            notes: [
                "規則觸發判斷由程式計算；模型僅生成說明，不修改門檻或判斷結果。",
                "目前 EventStore 預設保留 50 筆；已刪除的事件不在本次分析範圍。",
                "模型最多取得前 8 筆警示的精簡統計；完整 findings 保留在 ruleResult。",
                "觸發來源數（不重複來源）與警示數（Finding 筆數）分開計算。",
                "本模組選用裝置端 SystemLanguageModel，未配置遠端模型或網路請求。"
            ]
        )
    }

    func jsonData() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(self)
    }
}
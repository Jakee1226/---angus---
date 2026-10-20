import Foundation

// 以公開 c-analyzer-v2 分支中已核對的資料結構與規則重建。
// 原始版本：https://github.com/413580249/IR-C-Analyzer/blob/c-analyzer-v2/SecurityAnalyzer.swift
// 使用前務必與該分支最新提交比對；請勿與另一份 SecurityAnalyzer.swift 同時加入 target。
struct SecurityAnalysisRule: Codable {
    let windowSeconds: Int
    let threshold: Int
    let comparison: String
    enum CodingKeys: String, CodingKey {
        case windowSeconds = "window_seconds"
        case threshold, comparison
    }
}

struct SecurityFinding: Codable, Identifiable {
    let ruleID: String
    let source: String
    let risk: String
    let count: Int
    let windowStart: String
    let windowEnd: String
    let reason: String
    let recommendation: String
    var id: String { "\(ruleID):\(source)" }
    enum CodingKeys: String, CodingKey {
        case ruleID = "rule_id"
        case source, risk, count
        case windowStart = "window_start"
        case windowEnd = "window_end"
        case reason, recommendation
    }
}

struct SecurityAnalysisResult: Codable {
    let status: String
    let totalEvents: Int
    let rule: SecurityAnalysisRule
    let findings: [SecurityFinding]
    // V3.1: malformed timestamps are skipped, not interpreted as valid evidence.
    let invalidTimestampCount: Int
    init(status: String, totalEvents: Int, rule: SecurityAnalysisRule,
         findings: [SecurityFinding], invalidTimestampCount: Int = 0) {
        self.status = status
        self.totalEvents = totalEvents
        self.rule = rule
        self.findings = findings
        self.invalidTimestampCount = invalidTimestampCount
    }
    enum CodingKeys: String, CodingKey {
        case status
        case totalEvents = "total_events"
        case rule, findings
        case invalidTimestampCount = "invalid_timestamp_count"
    }
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        status = try c.decode(String.self, forKey: .status)
        totalEvents = try c.decode(Int.self, forKey: .totalEvents)
        rule = try c.decode(SecurityAnalysisRule.self, forKey: .rule)
        findings = try c.decode([SecurityFinding].self, forKey: .findings)
        invalidTimestampCount = try c.decodeIfPresent(Int.self, forKey: .invalidTimestampCount) ?? 0
    }
    func jsonString() throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        return String(decoding: try encoder.encode(self), as: UTF8.self)
    }
}

enum SecurityAnalysisError: LocalizedError {
    case invalidTimestamp(eventID: String, timestamp: String)
    var errorDescription: String? {
        switch self {
        case let .invalidTimestamp(eventID, timestamp):
            return "事件 \(eventID) 的時間格式錯誤：\(timestamp)。請使用含時區的 ISO 8601 格式。"
        }
    }
}

enum SecurityAnalyzer {
    static let windowSeconds = 60
    static let threshold = 10
    static let sensitiveTargets: Set<String> = ["test_private_file.txt"]
    static let multiFileThreshold = 5
    static let failedReadThreshold = 5

    private struct TimedEvent {
        let event: SecurityEvent
        let date: Date
    }
    private struct Peak {
        let count: Int
        let start: String
        let end: String
    }

    private static func parseDate(_ event: SecurityEvent) throws -> Date {
        let hasTimeZone = event.timestamp.range(
            of: "(Z|[+-][0-9]{2}:[0-9]{2})$", options: .regularExpression
        ) != nil
        let standard = ISO8601DateFormatter()
        standard.formatOptions = [.withInternetDateTime]
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        guard hasTimeZone,
              let date = fractional.date(from: event.timestamp) ?? standard.date(from: event.timestamp) else {
            throw SecurityAnalysisError.invalidTimestamp(
                eventID: event.eventID, timestamp: event.timestamp
            )
        }
        return date
    }

    static func shouldCount(_ event: SecurityEvent) -> Bool {
        event.action == "read" && event.result == "allowed" && sensitiveTargets.contains(event.target)
    }

    private static func findPeak(
        _ events: [TimedEvent], score: (ArraySlice<TimedEvent>) -> Int
    ) -> Peak? {
        guard !events.isEmpty else { return nil }
        let sorted = events.sorted { $0.date < $1.date }
        var left = 0
        var best: Peak?
        for right in sorted.indices {
            while sorted[right].date.timeIntervalSince(sorted[left].date) > Double(windowSeconds) {
                left += 1
            }
            let window = sorted[left...right]
            let count = score(window)
            if count > (best?.count ?? 0) {
                best = Peak(count: count,
                            start: sorted[left].event.timestamp,
                            end: sorted[right].event.timestamp)
            }
        }
        return best
    }

    static func analyze(events: [SecurityEvent]) throws -> SecurityAnalysisResult {
        var grouped: [String: [TimedEvent]] = [:]
        var invalidTimestampCount = 0
        for event in events {
            guard let date = try? parseDate(event) else {
                invalidTimestampCount += 1
                continue
            }
            grouped[event.source, default: []].append(TimedEvent(event: event, date: date))
        }
        var findings: [SecurityFinding] = []
        for source in grouped.keys.sorted() {
            guard let sourceEvents = grouped[source] else { continue }
            let sensitiveReads = sourceEvents.filter { shouldCount($0.event) }
            if let peak = findPeak(sensitiveReads, score: { $0.count }), peak.count > threshold {
                findings.append(SecurityFinding(
                    ruleID: "sensitive_read_burst", source: source, risk: "medium", count: peak.count,
                    windowStart: peak.start, windowEnd: peak.end,
                    reason: "\(windowSeconds) 秒內成功讀取敏感資料 \(peak.count) 次，超過門檻 \(threshold) 次。",
                    recommendation: "確認敏感資料存取是否符合預期。"
                ))
            }
            let successfulReads = sourceEvents.filter {
                $0.event.action == "read" && $0.event.result == "allowed"
            }
            if let peak = findPeak(successfulReads, score: { Set($0.map { $0.event.target }).count }),
               peak.count >= multiFileThreshold {
                findings.append(SecurityFinding(
                    ruleID: "multi_file_read", source: source, risk: "medium", count: peak.count,
                    windowStart: peak.start, windowEnd: peak.end,
                    reason: "\(windowSeconds) 秒內成功讀取 \(peak.count) 個不同檔案，達到多檔案偵測門檻。",
                    recommendation: "檢查是否存在非預期的批次檔案存取。"
                ))
            }
            let failedReads = sourceEvents.filter {
                $0.event.action == "read" && $0.event.result == "failed"
            }
            if let peak = findPeak(failedReads, score: { $0.count }), peak.count >= failedReadThreshold {
                findings.append(SecurityFinding(
                    ruleID: "repeated_read_failure", source: source, risk: "medium", count: peak.count,
                    windowStart: peak.start, windowEnd: peak.end,
                    reason: "\(windowSeconds) 秒內讀取失敗 \(peak.count) 次，達到失敗次數門檻。",
                    recommendation: "檢查檔案是否存在、操作權限及失敗原因。"
                ))
            }
        }
        return SecurityAnalysisResult(
            status: findings.isEmpty ? "no_rule_triggered" : "suspicious",
            totalEvents: events.count,
            rule: SecurityAnalysisRule(
                windowSeconds: windowSeconds, threshold: threshold, comparison: "greater_than"
            ),
            findings: findings,
            invalidTimestampCount: invalidTimestampCount
        )
    }
}

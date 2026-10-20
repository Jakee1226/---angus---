import Foundation

// 【待與 A 最新 Git 檔比對】按先前提供的事件契約重建，不冒充逐字原始碼。
struct SecurityEvent: Codable {
    let eventID: String
    let timestamp: String
    let source: String
    let action: String
    let target: String
    let result: String
    let isSimulated: Bool

    enum CodingKeys: String, CodingKey {
        case eventID = "event_id"
        case timestamp, source, action, target, result
        case isSimulated = "is_simulated"
    }

    static func nowTimestamp() -> String {
        let formatter = ISO8601DateFormatter()
        formatter.timeZone = .current
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.string(from: Date())
    }

    func jsonString() -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? encoder.encode(self) else { return "{}" }
        return String(decoding: data, as: UTF8.self)
    }
}

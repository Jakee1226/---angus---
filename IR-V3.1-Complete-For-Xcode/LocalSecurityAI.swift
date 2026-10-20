import Foundation
#if canImport(FoundationModels)
import FoundationModels
#endif

// 依先前提供的 B 模組程式碼還原的 V3 整合稿，尚未與 B 的最新 Git 版本比對。
@MainActor
protocol SecurityExplaining {
    var availability: SecurityAIAvailability { get }
    func explain(context: SecurityAIContext) async throws -> SecurityExplanation
}

@MainActor
final class LocalSecurityAI: SecurityExplaining {
    var availability: SecurityAIAvailability {
        #if canImport(FoundationModels)
        if #available(iOS 26.0, macOS 26.0, macCatalyst 26.0, visionOS 26.0, *) {
            switch SystemLanguageModel.default.availability {
            case .available:
                return SecurityAIAvailability(isAvailable: true, message: "本地模型可使用。")
            case .unavailable(.deviceNotEligible):
                return SecurityAIAvailability(isAvailable: false, message: "此裝置不支援本地 AI，將使用固定規則說明。")
            case .unavailable(.appleIntelligenceNotEnabled):
                return SecurityAIAvailability(isAvailable: false, message: "Apple Intelligence 尚未啟用，將使用固定規則說明。")
            case .unavailable(.modelNotReady):
                return SecurityAIAvailability(isAvailable: false, message: "本地模型尚未準備完成，將使用固定規則說明。")
            case .unavailable:
                return SecurityAIAvailability(isAvailable: false, message: "本地 AI 暫時無法使用，將使用固定規則說明。")
            @unknown default:
                return SecurityAIAvailability(isAvailable: false, message: "無法確認本地 AI 狀態，將使用固定規則說明。")
            }
        }
        return SecurityAIAvailability(isAvailable: false, message: "需要支援 Foundation Models 的系統版本。")
        #else
        return SecurityAIAvailability(isAvailable: false, message: "目前 SDK 不提供 Foundation Models，將使用固定規則說明。")
        #endif
    }

    func explain(context: SecurityAIContext) async throws -> SecurityExplanation {
        try Task.checkCancellation()
        let current = availability
        guard current.isAvailable else { throw SecurityAIError.unavailable(current.message) }
        #if canImport(FoundationModels)
        if #available(iOS 26.0, macOS 26.0, macCatalyst 26.0, visionOS 26.0, *) {
            return try await generate(context: context)
        }
        #endif
        throw SecurityAIError.unavailable(current.message)
    }

    #if canImport(FoundationModels)
    @available(iOS 26.0, macOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
    private func generate(context: SecurityAIContext) async throws -> SecurityExplanation {
        let prompt = "請根據這份已確定的事件統計產生說明：\n" + (try context.jsonString())
        let session = LanguageModelSession(
            model: SystemLanguageModel.default,
            instructions: SecurityAIInstructions.text
        )
        do {
            let response = try await session.respond(
                to: prompt,
                generating: GeneratedSecurityExplanation.self,
                options: GenerationOptions(temperature: 0.2)
            )
            try Task.checkCancellation()
            return try SecurityExplanation(
                origin: .onDeviceAI,
                summary: response.content.summary,
                whyItMatters: response.content.whyItMatters,
                recommendedNextStep: response.content.recommendedNextStep,
                limits: response.content.limits
            ).validated()
        } catch is CancellationError {
            throw CancellationError()
        } catch let error as SecurityAIError {
            throw error
        } catch {
            print("Local AI generation error type:", String(reflecting: type(of: error)))
            throw SecurityAIError.generationFailed
        }
    }
    #endif
}

#if canImport(FoundationModels)
@available(iOS 26.0, macOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
@Generable private struct GeneratedSecurityExplanation {
    @Guide(description: "用繁體中文，一到兩句概括已提供的三條規則的實際結果。")
    var summary: String
    @Guide(description: "用繁體中文簡述觸發行為為何需要確認，不認定是攻擊。")
    var whyItMatters: String
    @Guide(description: "用繁體中文建議核對預期操作或保留紀錄，不聲稱已執行動作。")
    var recommendedNextStep: String
    @Guide(description: "用繁體中文說明這只是 App 內事件，包含模擬資料時須指出限制。")
    var limits: String
}
#endif

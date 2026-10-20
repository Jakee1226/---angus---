import Foundation
import Combine

// 依先前提供的 B 模組內容整理；保留已知 public UI 介面及防舊結果覆蓋機制。
// 必須和 B 的最新 ViewModel diff 後再取代。
@MainActor
final class SecurityAnalysisViewModel: ObservableObject {
    @Published private(set) var ruleResult: SecurityAnalysisResult?
    @Published private(set) var explanation: SecurityExplanation?
    @Published private(set) var latestReport: SecurityIRReport?
    @Published private(set) var reports: [SecurityIRReport] = []
    @Published private(set) var isAnalyzing = false
    @Published private(set) var analysisError: String?
    @Published private(set) var explanationNotice: String?
    @Published private(set) var historyNotice: String?
    @Published private(set) var modelAvailability: SecurityAIAvailability

    private let explainer: any SecurityExplaining
    private let store: SecurityReportStore
    private var analysisTask: Task<Void, Never>?
    private var requestID: UUID?
    private var activeSnapshot: (events: [SecurityEvent], result: SecurityAnalysisResult, context: SecurityAIContext)?
    private var cachedSnapshot: Data?
    private var cachedExplanation: SecurityExplanation?

    init(explainer: (any SecurityExplaining)? = nil, store: SecurityReportStore? = nil) {
        let engine = explainer ?? LocalSecurityAI()
        let reportStore = store ?? SecurityReportStore()
        self.explainer = engine
        self.store = reportStore
        self.modelAvailability = engine.availability
        self.reports = reportStore.reports
        self.historyNotice = reportStore.loadErrorMessage
    }

    func refreshAvailability() { modelAvailability = explainer.availability }

    func invalidate() {
        analysisTask?.cancel()
        analysisTask = nil
        requestID = nil
        activeSnapshot = nil
        ruleResult = nil
        explanation = nil
        latestReport = nil
        analysisError = nil
        explanationNotice = nil
        isAnalyzing = false
    }

    func analyze(events: [SecurityEvent], useAI: Bool = true) {
        invalidate()
        refreshAvailability()
        let id = UUID()
        requestID = id
        let result: SecurityAnalysisResult
        do {
            result = try SecurityAnalyzer.analyze(events: events)
        } catch {
            analysisError = error.localizedDescription
            requestID = nil
            return
        }
        let context = SecurityAIContext.make(events: events, result: result)
        let snapshot = Self.snapshotData(events)
        activeSnapshot = (events, result, context)
        ruleResult = result

        if events.isEmpty || !useAI || !modelAvailability.isAvailable {
            let notice: String
            if events.isEmpty { notice = "目前沒有可分析事件，使用固定規則說明。" }
            else if !useAI { notice = "本地 AI 已關閉，使用固定規則說明。" }
            else { notice = modelAvailability.message }
            finish(id: id, events: events, result: result, context: context,
                   explanation: SecurityRuleExplanation.make(context: context), notice: notice)
            return
        }
        if let snapshot, snapshot == cachedSnapshot, let cached = cachedExplanation {
            finish(id: id, events: events, result: result, context: context,
                   explanation: cached, notice: "事件未改變，使用這批事件已有的本地 AI 說明。")
            return
        }

        isAnalyzing = true
        analysisTask = Task { @MainActor [weak self] in
            guard let self else { return }
            do {
                try Task.checkCancellation()
                let generated = try await self.explainer.explain(context: context)
                let validated = try generated.validated()
                try Task.checkCancellation()
                guard self.requestID == id else { return }
                if validated.origin == .onDeviceAI {
                    self.cachedSnapshot = snapshot
                    self.cachedExplanation = validated
                }
                self.finish(id: id, events: events, result: result, context: context,
                            explanation: validated, notice: nil)
            } catch is CancellationError {
                guard self.requestID == id else { return }
                self.finish(id: id, events: events, result: result, context: context,
                            explanation: SecurityRuleExplanation.make(context: context),
                            notice: "本地 AI 已取消，使用固定規則說明。")
            } catch {
                guard self.requestID == id else { return }
                self.finish(id: id, events: events, result: result, context: context,
                            explanation: SecurityRuleExplanation.make(context: context),
                            notice: "本地 AI 未能完成說明，使用固定規則說明。")
            }
        }
    }

    func stopWaiting() {
        guard isAnalyzing, let snapshot = activeSnapshot, let id = requestID else { return }
        analysisTask?.cancel()
        finish(id: id, events: snapshot.events, result: snapshot.result, context: snapshot.context,
               explanation: SecurityRuleExplanation.make(context: snapshot.context),
               notice: "已停止等待本地 AI，使用固定規則說明。")
    }

    func waitForCurrentAnalysis() async {
        let task = analysisTask
        await task?.value
    }

    func clearHistory() {
        do {
            try store.clear()
            reports = store.reports
            historyNotice = nil
        } catch {
            historyNotice = "無法清除歷史報告：\(error.localizedDescription)"
        }
    }

    private func finish(id: UUID, events: [SecurityEvent], result: SecurityAnalysisResult,
                        context: SecurityAIContext, explanation: SecurityExplanation, notice: String?) {
        guard requestID == id else { return }
        // Close this request BEFORE any state updates or persistence.
        // A cancelled AI task cannot finish this request twice.
        requestID = nil
        self.explanation = explanation
        explanationNotice = notice
        isAnalyzing = false
        activeSnapshot = nil
        analysisTask = nil
        let report = SecurityIRReport.make(events: events, ruleResult: result,
                                           context: context, explanation: explanation, notice: notice)
        latestReport = report
        do {
            try store.append(report)
            reports = store.reports
            historyNotice = nil
        } catch {
            historyNotice = "歷史報告未能保存；本次分析仍可查看及匯出。"
        }
    }

    private static func snapshotData(_ events: [SecurityEvent]) -> Data? {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try? encoder.encode(events)
    }
}

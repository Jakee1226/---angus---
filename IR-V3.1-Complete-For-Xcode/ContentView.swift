import SwiftUI
import Combine

// C 模組 v3-P0：修改自 v2 ContentView（尚未與 B 最新版比對）。完整畫面整合內容，替換既有 ContentView.swift。
// 與原 ContentView 保留一份定義；其餘 C 模組檔案新增到相同 App target。
@MainActor
struct ContentView: View {
    @Environment(\.scenePhase) private var scenePhase
    @StateObject private var collector = EventCollector()
    @StateObject private var analysis = SecurityAnalysisViewModel()
    @State private var events: [SecurityEvent] = []
    @State private var snapshotData: Data?
    @State private var useLocalAI = true
    @State private var exportURL: URL?
    @State private var exportError: String?
    @State private var confirmHistoryClear = false

    var body: some View {
        NavigationStack {
            List {
                header
                operations
                analysisSettings
                ruleResults
                explanationResults
                exportSection
                historySection
                eventList
            }
            .navigationTitle("Security Monitor")
        }
        .onAppear {
            TestFileService.prepare()
            refreshEventsIfChanged()
            analysis.refreshAvailability()
        }
        .onReceive(collector.$storedCount.dropFirst()) { _ in
            refreshEventsIfChanged()
        }
        .onChange(of: useLocalAI) { _ in
            analysis.invalidate()
            exportURL = nil
            exportError = nil
        }
        .onChange(of: scenePhase) { phase in
            if phase == .active {
                refreshEventsIfChanged()
                analysis.refreshAvailability()
            } else if phase == .background {
                analysis.stopWaiting()
            }
        }
        .alert("清除歷史報告？", isPresented: $confirmHistoryClear) {
            Button("保留", role: .cancel) {}
            Button("清除", role: .destructive) {
                analysis.clearHistory()
            }
        } message: {
            Text("將清除本機保存的分析歷史。本次畫面結果與事件紀錄仍保留。")
        }
    }

    private var header: some View {
        Section {
            VStack(spacing: 10) {
                Image(systemName: "shield.checkered")
                    .font(.system(size: 45))
                    .foregroundStyle(.blue)
                Text("AI 資安事件監控系統")
                    .font(.title2)
                    .bold()
                Text("App 內事件・規則判斷・本地說明")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 8)
        }
    }

    private var operations: some View {
        Section("事件操作") {
            Button(role: .destructive) {
                collector.clearEvents()
                refreshEventsIfChanged()
            } label: {
                Label("清除事件紀錄", systemImage: "trash")
            }
            .buttonStyle(.borderless)

            Button {
                readTestFile(count: 1)
            } label: {
                Label("讀取測試檔案", systemImage: "plus.circle")
            }
            .buttonStyle(.borderless)

            Button {
                collector.readFile(named: "missing_file", target: "missing_file")
                refreshEventsIfChanged()
            } label: {
                Label("讀取不存在的檔案", systemImage: "xmark.circle")
            }
            .buttonStyle(.borderless)

            #if DEBUG
            Button {
                collector.printStoredEvents()
            } label: {
                Label("輸出事件 JSON 到 Console", systemImage: "doc.text")
            }
            .buttonStyle(.borderless)

            Button {
                readTestFile(count: 11)
            } label: {
                Label("連續讀取測試檔 11 次", systemImage: "repeat")
            }
            .buttonStyle(.borderless)

            Button {
                TestFileService.prepareBatchFiles()
                collector.readFiles(named: TestFileService.batchScenarioFileNames)
                refreshEventsIfChanged()
            } label: {
                Label("多檔案讀取情境（5 成功＋1 失敗）", systemImage: "doc.on.doc")
            }
            .buttonStyle(.borderless)
            #endif

            Button {
                exportURL = nil
                exportError = nil
                analysis.analyze(events: collector.events, useAI: useLocalAI)
            } label: {
                Label("分析已儲存事件", systemImage: "magnifyingglass")
            }
            .buttonStyle(.borderless)
            .disabled(analysis.isAnalyzing)
        }
    }

    private var analysisSettings: some View {
        Section("說明方式") {
            Toggle("可用時使用本地 AI 說明", isOn: $useLocalAI)
            Text(analysis.modelAvailability.message)
                .font(.caption)
                .foregroundStyle(.secondary)
            Button("重新檢查模型狀態") {
                analysis.refreshAvailability()
            }
            .buttonStyle(.borderless)
        }
    }

    @ViewBuilder
    private var ruleResults: some View {
        Section("C 模組：規則結果") {
            Text("系統可偵測短時間敏感資料大量讀取、多檔案讀取與連續讀取失敗。")
                .font(.subheadline)
            if let error = analysis.analysisError {
                Text(error).foregroundStyle(.red)
            } else if let result = analysis.ruleResult {
                LabeledContent("分析事件", value: "\(result.totalEvents) 筆")
                LabeledContent("異常來源", value: "\(result.distinctSourceCount) 個")
                LabeledContent("觸發警示", value: "\(result.findings.count) 筆")
                if result.findings.isEmpty {
                    Text("未達任何規則的設定門檻")
                        .foregroundStyle(.secondary)
                }
                ForEach(result.findings) { finding in
                    SecurityFindingRow(finding: finding)
                }
            } else {
                Text("請按「分析已儲存事件」。")
                    .foregroundStyle(.secondary)
            }
            Text("目前預設只保留最新 50 筆事件；這項結果不代表整支手機的安全狀態。")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    @ViewBuilder
    private var explanationResults: some View {
        Section("事件說明") {
            if analysis.isAnalyzing {
                ProgressView("本地 AI 正在產生說明，規則結果已可查看。")
                Button("停止等待 AI，保留規則說明") {
                    analysis.stopWaiting()
                }
                .buttonStyle(.borderless)
            } else if let explanation = analysis.explanation {
                SecurityExplanationRows(explanation: explanation)
                if let notice = analysis.explanationNotice {
                    Text(notice)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                if let report = analysis.latestReport, !report.context.findingFacts.isEmpty {
                    Text(aliasLegend(report))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            } else {
                Text("分析後會顯示本地 AI 或固定規則的說明。")
                    .foregroundStyle(.secondary)
            }
        }
    }

    @ViewBuilder
    private var exportSection: some View {
        Section("分析報告") {
            if let report = analysis.latestReport {
                Button {
                    prepareExport(report)
                } label: {
                    Label("準備 JSON 報告", systemImage: "doc.badge.plus")
                }
                .buttonStyle(.borderless)
                if let url = exportURL {
                    ShareLink(item: url) {
                        Label("分享或儲存報告", systemImage: "square.and.arrow.up")
                    }
                }
                Text("報告包含本批事件欄位、規則結果與說明來源，不包含讀取的檔案內容。")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                Text("完成分析後即可匯出。")
                    .foregroundStyle(.secondary)
            }
            if let error = exportError {
                Text(error).foregroundStyle(.red)
            }
        }
    }

    @ViewBuilder
    private var historySection: some View {
        Section("本機分析歷史：\(analysis.reports.count) 份") {
            Text("最多保留最近 10 份完整分析報告。")
                .font(.caption)
                .foregroundStyle(.secondary)
            if let notice = analysis.historyNotice {
                Text(notice)
                    .font(.caption)
                    .foregroundStyle(.orange)
            }
            ForEach(analysis.reports) { report in
                NavigationLink {
                    SecurityArchivedReportView(report: report)
                } label: {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(report.ruleResult.findings.isEmpty ? "未觸發任何規則" : "\(report.ruleResult.findings.count) 筆警示・\(report.ruleResult.distinctSourceCount) 個來源")
                        Text("\(report.ruleResult.totalEvents) 筆事件・\(report.explanation.origin.displayName)")
                            .font(.caption)
                        Text(report.generatedAt)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            if !analysis.reports.isEmpty || analysis.historyNotice != nil {
                Button("清除分析歷史", role: .destructive) {
                    confirmHistoryClear = true
                }
                .buttonStyle(.borderless)
            }
        }
    }

    private var eventList: some View {
        Section("目前事件紀錄：\(events.count) 筆") {
            ForEach(events, id: \.eventID) { event in
                NavigationLink {
                    EventDetailView(event: event, analysis: analysis)
                } label: {
                    VStack(alignment: .leading, spacing: 6) {
                        Text(event.action.uppercased()).font(.headline)
                        Text("來源：\(event.source)")
                        Text("目標：\(event.target)")
                        Text("結果：\(event.result)")
                        Text(event.timestamp)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Text(event.isSimulated ? "模擬事件" : "非模擬事件")
                            .font(.caption)
                            .foregroundStyle(.orange)
                    }
                    .padding(.vertical, 5)
                }
            }
        }
    }

    private func readTestFile(count: Int) {
        for _ in 0..<count {
            collector.readFile(named: TestFileService.defaultFileName,
                               target: TestFileService.defaultFileName)
        }
        refreshEventsIfChanged()
    }

    private func refreshEventsIfChanged() {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let latest = try? encoder.encode(collector.events)
        guard latest != snapshotData else { return }
        snapshotData = latest
        events = Array(collector.events.reversed())
        analysis.invalidate()
        exportURL = nil
        exportError = nil
    }

    private func prepareExport(_ report: SecurityIRReport) {
        do {
            exportURL = try SecurityReportExporter.prepareFile(report: report)
            exportError = nil
        } catch {
            exportURL = nil
            exportError = "報告檔案未能建立，請稍後再試。"
        }
    }

    private func aliasLegend(_ report: SecurityIRReport) -> String {
        let used = Set(report.context.findingFacts.map { $0.sourceAlias })
        let mappings = report.sourceAliases.filter { used.contains($0.alias) }
        return "說明代號：" + mappings.map { "\($0.alias)＝\($0.source)" }.joined(separator: "；")
    }
}

@MainActor
struct SecurityFindingRow: View {
    let finding: SecurityFinding

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(SecurityRuleInfo.displayName(for: finding.ruleID)).font(.headline)
            Text("觸發來源：\(finding.source)")
            Text("數量：\(finding.count) \(SecurityRuleInfo.countUnitLabel(for: finding.ruleID))")
            Text(finding.reason)
            Text("規則風險等級：\(finding.risk == "medium" ? "中" : finding.risk == "high" ? "高" : finding.risk == "low" ? "低" : "未分類")")
                .font(.caption)
            Text("時間：\(finding.windowStart) ～ \(finding.windowEnd)")
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(finding.recommendation)
                .foregroundStyle(.secondary)
        }
        .padding(.vertical, 4)
    }
}

@MainActor
struct SecurityExplanationRows: View {
    let explanation: SecurityExplanation

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(explanation.origin.displayName).font(.headline)
            explanationField("摘要", explanation.summary)
            explanationField("如何理解", explanation.whyItMatters)
            explanationField("建議下一步", explanation.recommendedNextStep)
            explanationField("分析限制", explanation.limits)
            if explanation.origin == .onDeviceAI {
                Text("AI 文字可能有誤；觸發來源、次數與時間以規則結果為準。")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 4)
    }

    private func explanationField(_ title: String, _ text: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title).font(.subheadline).bold()
            Text(text)
        }
    }
}

@MainActor
struct EventDetailView: View {
    let event: SecurityEvent
    @ObservedObject var analysis: SecurityAnalysisViewModel

    private var findings: [SecurityFinding] {
        analysis.ruleResult?.findings.filter { $0.source == event.source } ?? []
    }

    private var eventRoleText: String {
        let ids = SecurityRuleInfo.participatingRuleIDs(for: event)
        if ids.isEmpty { return "這筆事件不會被目前三條規則計入（規則只計算讀取事件）。" }
        let names = ids.map { SecurityRuleInfo.displayName(for: $0) }.joined(separator: "、")
        return "這筆事件會被計入：\(names)。是否觸發，取決於同來源整批事件是否達到門檻。"
    }

    var body: some View {
        Form {
            Section("事件基本資訊") {
                LabeledContent("事件 ID", value: event.eventID)
                LabeledContent("時間", value: event.timestamp)
                LabeledContent("來源", value: event.source)
            }
            Section("事件內容") {
                LabeledContent("動作", value: event.action)
                LabeledContent("目標", value: event.target)
                LabeledContent("結果", value: event.result)
                Text(event.isSimulated ? "模擬事件" : "非模擬事件")
            }
            Section("同來源的批次規則結果") {
                if let result = analysis.ruleResult {
                    Text("分析的是整批 \(result.totalEvents) 筆事件；這裡只顯示此來源的結果。")
                        .font(.caption)
                    Text(eventRoleText)
                    if findings.isEmpty {
                        Text("此來源未觸發任何規則。")
                    }
                    ForEach(findings) { finding in
                        SecurityFindingRow(finding: finding)
                    }
                    Text("同來源的警示不代表這筆事件單獨構成攻擊。")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else {
                    Text("請先回主畫面分析目前事件。")
                }
            }
            Section("本批事件的說明") {
                if analysis.isAnalyzing {
                    ProgressView("正在生成本地 AI 說明。")
                } else if let explanation = analysis.explanation {
                    SecurityExplanationRows(explanation: explanation)
                } else {
                    Text("目前沒有完成的說明。")
                }
            }
        }
        .navigationTitle("事件詳細資訊")
    }
}

@MainActor
struct SecurityArchivedReportView: View {
    let report: SecurityIRReport
    @State private var exportURL: URL?
    @State private var exportError: String?

    var body: some View {
        Form {
            Section("歷史報告") {
                LabeledContent("時間", value: report.generatedAt)
                LabeledContent("版本", value: report.moduleVersion)
                LabeledContent("事件數", value: "\(report.ruleResult.totalEvents)")
                LabeledContent("異常來源", value: "\(report.ruleResult.distinctSourceCount)")
                LabeledContent("觸發警示", value: "\(report.ruleResult.findings.count)")
                Text("這是保存時的事件快照，與目前事件列表分開。")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                if report.schemaVersion == "1.0" {
                    Text("這是舊版格式報告；上方來源數與警示數由保存的規則結果重新計算。")
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
            }
            Section("規則結果") {
                if report.ruleResult.findings.isEmpty {
                    Text("這批事件未觸發任何規則。")
                }
                ForEach(report.ruleResult.findings) { finding in
                    SecurityFindingRow(finding: finding)
                }
            }
            Section("保存的說明") {
                SecurityExplanationRows(explanation: report.explanation)
                if let notice = report.explanationNotice {
                    Text(notice).font(.caption)
                }
            }
            Section("來源代號") {
                ForEach(report.sourceAliases) { source in
                    LabeledContent(source.alias, value: source.source)
                }
            }
            Section("匯出") {
                Button("準備這份 JSON 報告") {
                    do {
                        exportURL = try SecurityReportExporter.prepareFile(report: report)
                        exportError = nil
                    } catch {
                        exportURL = nil
                        exportError = "報告檔案未能建立，請稍後再試。"
                    }
                }
                if let url = exportURL {
                    ShareLink(item: url) {
                        Label("分享或儲存報告", systemImage: "square.and.arrow.up")
                    }
                }
                if let error = exportError {
                    Text(error).foregroundStyle(.red)
                }
            }
        }
        .navigationTitle("分析報告")
    }
}

#Preview {
    ContentView()
}

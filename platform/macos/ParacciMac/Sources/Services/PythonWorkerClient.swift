import Foundation

enum WorkerClientError: Error, LocalizedError {
    case workerNotFound
    case processExited
    case invalidResponse
    case timeout
    case apiError(String)

    var errorDescription: String? {
        switch self {
        case .workerNotFound:
            return "The bundled Python worker could not be found."
        case .processExited:
            return "The Python worker exited unexpectedly."
        case .invalidResponse:
            return "The Python worker returned an invalid response."
        case .timeout:
            return "The operation timed out."
        case .apiError(let message):
            return message
        }
    }
}

actor PythonWorkerClient {
    private let workerURLOverride: URL?
    private let dataDirectoryURL: URL?
    private var process: Process?
    private var inputPipe: Pipe?
    private var outputPipe: Pipe?
    private var errorPipe: Pipe?
    private var outputBuffer = Data()
    private var errorBuffer = Data()

    init(workerURL: URL? = nil, dataDirectoryURL: URL? = nil) {
        self.workerURLOverride = workerURL
        self.dataDirectoryURL = dataDirectoryURL
    }

    func call(method: String, params: [String: Any] = [:], timeout: TimeInterval = 30.0) async throws -> [String: Any] {
        try ensureStarted()
        let requestID = UUID().uuidString
        let payload: [String: Any] = [
            "id": requestID,
            "method": method,
            "params": params
        ]
        let data = try JSONSerialization.data(withJSONObject: payload)
        guard let line = String(data: data, encoding: .utf8) else {
            throw WorkerClientError.invalidResponse
        }
        
        try write(line + "\n")
        let response = try await readResponseLine(timeout: timeout)
        let result = try decodeResponse(response, expectedID: requestID)
        return result
    }

    func stop() {
        outputPipe?.fileHandleForReading.readabilityHandler = nil
        errorPipe?.fileHandleForReading.readabilityHandler = nil
        process?.terminate()
        process = nil
        inputPipe = nil
        outputPipe = nil
        errorPipe = nil
        outputBuffer.removeAll(keepingCapacity: false)
        errorBuffer.removeAll(keepingCapacity: false)
    }

    private func ensureStarted() throws {
        if let process, process.isRunning {
            return
        }

        let workerURL = try resolveWorkerURL()
        let process = Process()
        let inputPipe = Pipe()
        let outputPipe = Pipe()
        let errorPipe = Pipe()

        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        var arguments = ["python3", workerURL.path]
        if let dataDirectoryURL {
            arguments.append(contentsOf: ["--data-dir", dataDirectoryURL.path])
        }
        process.arguments = arguments
        process.standardInput = inputPipe
        process.standardOutput = outputPipe
        process.standardError = errorPipe
        process.environment = ProcessInfo.processInfo.environment.merging(["PYTHONUNBUFFERED": "1"]) { _, new in new }

        // Start reading stdout in background to prevent pipe deadlock
        outputPipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty else { return }
            Task { [weak self] in
                await self?.appendOutput(data)
            }
        }

        // Start reading stderr in background to prevent pipe deadlock
        errorPipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty else { return }
            Task { [weak self] in
                await self?.appendError(data)
            }
        }

        try process.run()
        self.process = process
        self.inputPipe = inputPipe
        self.outputPipe = outputPipe
        self.errorPipe = errorPipe
        self.outputBuffer.removeAll(keepingCapacity: false)
        self.errorBuffer.removeAll(keepingCapacity: false)
    }

    private func appendOutput(_ data: Data) {
        outputBuffer.append(data)
    }

    private func appendError(_ data: Data) {
        errorBuffer.append(data)
    }

    private func resolveWorkerURL() throws -> URL {
        if let workerURLOverride, FileManager.default.fileExists(atPath: workerURLOverride.path) {
            return workerURLOverride
        }

        let environment = ProcessInfo.processInfo.environment
        if let explicit = environment["PARACCI_WORKER_PATH"], FileManager.default.fileExists(atPath: explicit) {
            return URL(fileURLWithPath: explicit)
        }

        if let bundled = Bundle.main.url(forResource: "worker", withExtension: "py", subdirectory: "paracci/bridge") {
            return bundled
        }

        let cwd = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        let candidates = [
            cwd.appendingPathComponent("paracci/bridge/worker.py"),
            cwd.appendingPathComponent("../../paracci/bridge/worker.py"),
            cwd.appendingPathComponent("../../../paracci/bridge/worker.py"),
            cwd.appendingPathComponent("../../../../paracci/bridge/worker.py")
        ]
        for candidate in candidates where FileManager.default.fileExists(atPath: candidate.standardized.path) {
            return candidate.standardized
        }

        throw WorkerClientError.workerNotFound
    }

    private func write(_ line: String) throws {
        guard let data = line.data(using: .utf8), let input = inputPipe?.fileHandleForWriting else {
            throw WorkerClientError.processExited
        }
        try input.write(contentsOf: data)
    }

    private func readResponseLine(timeout: TimeInterval) async throws -> String {
        let start = Date()
        let newline = Data([0x0A])
        
        while Date().timeIntervalSince(start) < timeout {
            if let range = outputBuffer.range(of: newline) {
                let lineData = outputBuffer.subdata(in: outputBuffer.startIndex..<range.lowerBound)
                outputBuffer.removeSubrange(outputBuffer.startIndex...range.lowerBound)
                
                guard let line = String(data: lineData, encoding: .utf8) else {
                    throw WorkerClientError.invalidResponse
                }
                return line
            }
            
            if let process, !process.isRunning {
                throw WorkerClientError.processExited
            }
            
            // Wait briefly before polling again
            try await Task.sleep(nanoseconds: 50_000_000) // 50ms
        }
        
        throw WorkerClientError.timeout
    }

    private func decodeResponse(_ line: String, expectedID: String) throws -> [String: Any] {
        guard
            let data = line.data(using: .utf8),
            let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
            let ok = object["ok"] as? Bool
        else {
            throw WorkerClientError.invalidResponse
        }

        if let id = object["id"] as? String, id != expectedID {
            throw WorkerClientError.invalidResponse
        }

        if ok {
            return object["result"] as? [String: Any] ?? [:]
        }

        let error = object["error"] as? [String: Any]
        var message = error?["message"] as? String ?? "The worker rejected the request."
        
        // Include stderr if available for better debugging
        if !errorBuffer.isEmpty, let stderr = String(data: errorBuffer, encoding: .utf8) {
            message += "\nWorker Stderr:\n\(stderr)"
        }
        
        throw WorkerClientError.apiError(message)
    }
}

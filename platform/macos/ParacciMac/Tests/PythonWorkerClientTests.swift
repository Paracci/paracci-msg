import XCTest
@testable import ParacciMac

final class PythonWorkerClientTests: XCTestCase {
    func testDeviceStatusRoundTripAgainstPythonWorker() async throws {
        let workerURL = try findWorkerURL()
        let dataURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("paracci-mac-worker-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dataURL, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dataURL) }

        let client = PythonWorkerClient(workerURL: workerURL, dataDirectoryURL: dataURL)
        
        do {
            let result = try await client.call(method: "device_status")
            XCTAssertEqual(result["initialized"] as? Bool, false)
            XCTAssertEqual(result["unlocked"] as? Bool, false)
            
            let expectedPath = dataURL.resolvingSymlinksInPath().path
            let actualPath = (result["data_dir"] as? String).map { URL(fileURLWithPath: $0).resolvingSymlinksInPath().path }
            XCTAssertEqual(actualPath, expectedPath)
            
            await client.stop()
        } catch {
            await client.stop()
            throw error
        }
    }

    private func findWorkerURL() throws -> URL {
        let environment = ProcessInfo.processInfo.environment
        if let explicit = environment["PARACCI_WORKER_PATH"], FileManager.default.fileExists(atPath: explicit) {
            return URL(fileURLWithPath: explicit)
        }

        let cwd = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        let candidates = [
            cwd.appendingPathComponent("paracci/bridge/worker.py"),
            cwd.appendingPathComponent("../../paracci/bridge/worker.py"),
            cwd.appendingPathComponent("../../../paracci/bridge/worker.py"),
            cwd.appendingPathComponent("../../../../paracci/bridge/worker.py")
        ]
        if let workerURL = candidates.first(where: { FileManager.default.fileExists(atPath: $0.standardized.path) }) {
            return workerURL.standardized
        }

        throw XCTSkip("Python worker not available in this checkout.")
    }
}

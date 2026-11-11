import Foundation
import Darwin
import NetGuardCore

enum PlatformPaths {
    static func policyDirectory() throws -> URL {
        guard !BuildIdentity.appGroupID.isEmpty,
              let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: BuildIdentity.appGroupID) else {
            throw PlatformError.unavailableContainer
        }
        return container.appendingPathComponent("RootPolicy", isDirectory: true)
    }

    static func bootSessionID() -> String {
        var length = 0
        guard sysctlbyname("kern.bootsessionuuid", nil, &length, nil, 0) == 0, length > 1, length < 256 else { return "" }
        var bytes = [CChar](repeating: 0, count: length)
        guard sysctlbyname("kern.bootsessionuuid", &bytes, &length, nil, 0) == 0 else { return "" }
        return String(cString: bytes)
    }
}

final class PolicyFileStore {
    private let directory: URL
    private let filename = "policy.json"
    private let maximumSize = 1_048_576
    init(directory: URL) { self.directory = directory }

    private func directoryDescriptor(create: Bool) throws -> Int32 {
        if create {
            guard geteuid() == 0 else { throw PlatformError.unsafePolicy }
            if mkdir(directory.path, 0o755) != 0 && errno != EEXIST { throw PlatformError.unsafePolicy }
        }
        let descriptor = open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw PlatformError.unsafePolicy }
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0, metadata.st_uid == 0,
              metadata.st_mode & 0o022 == 0 else {
            close(descriptor)
            throw PlatformError.unsafePolicy
        }
        return descriptor
    }

    func read(now: TimeInterval) throws -> PolicySnapshot {
        let folder = try directoryDescriptor(create: false)
        defer { close(folder) }
        let descriptor = openat(folder, filename, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard descriptor >= 0 else { throw PlatformError.unsafePolicy }
        defer { close(descriptor) }
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0, metadata.st_uid == 0,
              metadata.st_mode & S_IFMT == S_IFREG, metadata.st_mode & 0o022 == 0,
              metadata.st_nlink == 1, metadata.st_size > 0, metadata.st_size <= maximumSize else {
            throw PlatformError.unsafePolicy
        }
        var bytes = [UInt8](repeating: 0, count: Int(metadata.st_size))
        var total = 0
        while total < bytes.count {
            let count = bytes.withUnsafeMutableBytes { buffer in
                Darwin.read(descriptor, buffer.baseAddress!.advanced(by: total), buffer.count - total)
            }
            guard count > 0 else { throw PlatformError.unsafePolicy }
            total += count
        }
        let snapshot = try JSONDecoder().decode(PolicySnapshot.self, from: Data(bytes))
        try validate(snapshot, now: now)
        return snapshot
    }

    static func isFresh(_ snapshot: PolicySnapshot, now: TimeInterval) -> Bool {
        let boot = PlatformPaths.bootSessionID()
        return !boot.isEmpty && snapshot.bootSessionID == boot && now.isFinite &&
            snapshot.generatedAt.isFinite && snapshot.expiresAt.isFinite &&
            snapshot.generatedAt <= now && snapshot.expiresAt > now &&
            snapshot.expiresAt > snapshot.generatedAt && snapshot.expiresAt - snapshot.generatedAt <= 10
    }

    private func validate(_ snapshot: PolicySnapshot, now: TimeInterval) throws {
        guard Self.isFresh(snapshot, now: now) else { throw PlatformError.unsafePolicy }
    }

    func write(_ snapshot: PolicySnapshot) throws {
        guard geteuid() == 0 else { throw PlatformError.unsafePolicy }
        try validate(snapshot, now: ProcessInfo.processInfo.systemUptime)
        let bytes = try JSONEncoder().encode(snapshot)
        guard bytes.count <= maximumSize else { throw PlatformError.unsafePolicy }
        let folder = try directoryDescriptor(create: true)
        defer { close(folder) }
        let temporary = ".policy-" + UUID().uuidString
        let descriptor = openat(folder, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o644)
        guard descriptor >= 0 else { throw PlatformError.unsafePolicy }
        defer { close(descriptor); unlinkat(folder, temporary, 0) }
        var total = 0
        while total < bytes.count {
            let count = bytes.withUnsafeBytes { buffer in
                Darwin.write(descriptor, buffer.baseAddress!.advanced(by: total), buffer.count - total)
            }
            guard count > 0 else { throw PlatformError.unsafePolicy }
            total += count
        }
        guard fchmod(descriptor, 0o644) == 0, fsync(descriptor) == 0,
              renameat(folder, temporary, folder, filename) == 0, fsync(folder) == 0 else {
            throw PlatformError.unsafePolicy
        }
    }
}

final class PolicyCache {
    private let store: PolicyFileStore
    private let queue = DispatchQueue(label: "app.netguard.policy-cache")
    private let lock = NSLock()
    private var timer: DispatchSourceTimer?
    private var value: PolicySnapshot?
    private var refreshedAt: TimeInterval = 0
    private let bootSessionID = PlatformPaths.bootSessionID()
    init(store: PolicyFileStore) { self.store = store }

    func start() {
        queue.sync {
            guard timer == nil else { return }
            refresh()
            let timer = DispatchSource.makeTimerSource(queue: queue)
            timer.schedule(deadline: .now(), repeating: .milliseconds(200), leeway: .milliseconds(10))
            timer.setEventHandler { [weak self] in self?.refresh() }
            self.timer = timer
            timer.resume()
        }
    }

    func stop() {
        queue.sync {
            timer?.cancel()
            timer = nil
            lock.lock()
            value = nil
            lock.unlock()
        }
    }

    private func refresh() {
        let now = ProcessInfo.processInfo.systemUptime
        let next = try? store.read(now: now)
        lock.lock()
        value = next
        refreshedAt = now
        lock.unlock()
    }

    func snapshot(now: TimeInterval) -> PolicySnapshot? {
        lock.lock()
        defer { lock.unlock() }
        guard let value, !bootSessionID.isEmpty, value.bootSessionID == bootSessionID,
              now >= refreshedAt, now - refreshedAt <= 0.25,
              now >= value.generatedAt, now < value.expiresAt else { return nil }
        return value
    }
}

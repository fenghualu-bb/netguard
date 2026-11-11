import Foundation
import Darwin

// These probes measure the helper's system-routed connection only. They do
// not establish Claude's exit IP or prove ownership of any tunnel interface.
enum TraceProbe {
    static func validIP(_ candidate: String) -> Bool {
        var v4 = in_addr()
        var v6 = in6_addr()
        return candidate.withCString { inet_pton(AF_INET, $0, &v4) == 1 || inet_pton(AF_INET6, $0, &v6) == 1 }
    }

    static func fetch(completion: @escaping ([String?]) -> Void) {
        let endpoints = ["https://www.cloudflare.com/cdn-cgi/trace", "https://1.1.1.1/cdn-cgi/trace"]
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 5
        config.timeoutIntervalForResource = 8
        config.urlCache = nil
        let session = URLSession(configuration: config)
        let group = DispatchGroup()
        let queue = DispatchQueue(label: "app.netguard.trace-results")
        var values: [String?] = [nil, nil]
        for (index, endpoint) in endpoints.enumerated() {
            guard let url = URL(string: endpoint) else { continue }
            group.enter()
            session.dataTask(with: url) { data, response, error in
                defer { group.leave() }
                guard error == nil, (response as? HTTPURLResponse)?.statusCode == 200,
                      let data, data.count <= 8192,
                      let body = String(data: data, encoding: .utf8),
                      let line = body.split(separator: "\n").first(where: { $0.hasPrefix("ip=") }) else { return }
                let address = String(line.dropFirst(3)).trimmingCharacters(in: .whitespacesAndNewlines)
                guard validIP(address) else { return }
                queue.sync { values[index] = address }
            }.resume()
        }
        group.notify(queue: queue) { completion(values); session.finishTasksAndInvalidate() }
    }
}

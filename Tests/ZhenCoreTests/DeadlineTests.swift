import Foundation
import Testing
@testable import ZhenCore

@Suite("Deadlines and bounded work")
struct DeadlineTests {
    @Test("A child budget can shorten a parent's but never extend it")
    func clamping() {
        let parent = Deadline(after: .seconds(5))
        let greedy = Deadline(after: .seconds(60)).clamped(to: parent)
        let modest = Deadline(after: .seconds(1)).clamped(to: parent)

        #expect(greedy.instant == parent.instant)
        #expect(modest.instant < parent.instant)
    }

    @Test("An expired deadline reports zero remaining, never negative")
    func neverNegative() {
        let past = Deadline(after: .milliseconds(-500))
        #expect(past.remaining == .zero)
        #expect(past.isExpired)
    }

    @Test("Every item completes when the budget is generous")
    func completesWithinBudget() async {
        let items = Array(1...50)
        let results = await boundedPool(
            over: items,
            concurrency: 8,
            deadline: Deadline(after: .seconds(10))
        ) { item in
            .observed(item * 2)
        }
        #expect(results.results.count == 50)
        #expect(results.results[25] == 50)
    }

    @Test("Expiry yields partial results rather than nothing")
    func partialOnExpiry() async {
        let items = Array(1...200)
        let results = await boundedPool(
            over: items,
            concurrency: 4,
            deadline: Deadline(after: .milliseconds(200))
        ) { item in
            // Slower than the budget allows for all of them.
            try? await Task.sleep(for: .milliseconds(20))
            return .observed(item)
        }
        #expect(results.results.count < items.count)
    }

    @Test("A nil result is a data point, not a failure")
    func nilResultsAreDropped() async {
        let results = await boundedPool(
            over: Array(1...10),
            concurrency: 4,
            deadline: Deadline(after: .seconds(5))
        ) { item in
            // `.silent` rather than `nil`: an Optional here would bind Out to the
            // Optional itself and nothing would ever be dropped. See BoundedPool.swift.
            item.isMultiple(of: 2) ? .observed(item) : .silent
        }
        #expect(results.results.count == 5)
        #expect(results.results[3] == nil)
    }

    @Test("Progress reports reach the caller")
    func progressIsReported() async {
        let counter = Counter()
        _ = await boundedPool(
            over: Array(1...20),
            concurrency: 5,
            deadline: Deadline(after: .seconds(5)),
            onProgress: { completed, total in counter.record(completed, of: total) }
        ) { .observed($0) }
        #expect(counter.highWaterMark == 20)
    }
}

/// Minimal thread-safe box; the pool calls onProgress from arbitrary tasks.
final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0
    var highWaterMark: Int { lock.withLock { value } }
    func record(_ completed: Int, of total: Int) {
        lock.withLock { value = max(value, completed) }
    }
}

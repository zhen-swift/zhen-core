import Testing
@testable import ZhenCore

@Suite("Expiry queue")
struct ExpiryQueueTests {
    private let origin = MonotonicInstant.now

    private func at(_ millis: Int) -> MonotonicInstant {
        origin.advanced(by: .milliseconds(millis))
    }

    @Test("Keys come out in deadline order, and only once they are due")
    func ordersByDeadline() {
        var queue = ExpiryQueue<Int>()
        queue.schedule(3, at: at(30))
        queue.schedule(1, at: at(10))
        queue.schedule(2, at: at(20))

        #expect(queue.nextDeadline() == at(10))
        #expect(queue.popFirst(dueBy: at(5)) == nil)
        #expect(queue.popFirst(dueBy: at(25)) == 1)
        #expect(queue.popFirst(dueBy: at(25)) == 2)
        #expect(queue.popFirst(dueBy: at(25)) == nil)
        #expect(queue.count == 1)
        #expect(queue.popFirst(dueBy: at(30)) == 3)
        #expect(queue.isEmpty)
        #expect(queue.nextDeadline() == nil)
    }

    @Test("Equal deadlines come out in the order they were scheduled, never in hash order")
    func tiesAreStable() {
        var queue = ExpiryQueue<String>()
        let keys = (0..<200).map { "probe-\($0)" }
        for key in keys { queue.schedule(key, at: at(10)) }
        var out: [String] = []
        while let key = queue.popFirst(dueBy: at(10)) { out.append(key) }
        #expect(out == keys)
    }

    @Test("A cancelled key never comes out, and its deadline stops counting")
    func cancelRemoves() {
        var queue = ExpiryQueue<Int>()
        queue.schedule(1, at: at(10))
        queue.schedule(2, at: at(20))
        queue.cancel(1)
        queue.cancel(99)   // not scheduled: a no-op, not a crash
        #expect(!queue.contains(1))
        #expect(queue.count == 1)
        #expect(queue.nextDeadline() == at(20))
        #expect(queue.popFirst(dueBy: at(100)) == 2)
        #expect(queue.popFirst(dueBy: at(100)) == nil)
    }

    @Test("Rescheduling replaces the old deadline rather than adding a second")
    func rescheduleReplaces() {
        var queue = ExpiryQueue<Int>()
        queue.schedule(7, at: at(10))
        queue.schedule(7, at: at(50))
        #expect(queue.count == 1)
        #expect(queue.popFirst(dueBy: at(20)) == nil)
        #expect(queue.popFirst(dueBy: at(50)) == 7)
        #expect(queue.popFirst(dueBy: at(50)) == nil)
    }

    @Test("Mass cancellation leaves the queue correct after it compacts")
    func compactionKeepsLiveEntries() {
        var queue = ExpiryQueue<Int>()
        for key in 0..<1_000 { queue.schedule(key, at: at(key)) }
        for key in 0..<1_000 where key % 10 != 0 { queue.cancel(key) }
        #expect(queue.count == 100)
        var out: [Int] = []
        while let key = queue.popFirst(dueBy: at(1_000)) { out.append(key) }
        #expect(out == Array(stride(from: 0, to: 1_000, by: 10)))
    }

    // Gate G8 of the 0.8.0 brief. A /16 at three attempts is 65,536 × 3 transmissions.
    // The old engines walked every one of them on every wake; this asserts the queue's
    // work per operation is logarithmic, by counting comparisons — deterministic on any
    // machine, where a wall-clock benchmark would be a flaky test.
    @Test("A /16 sweep's bookkeeping is O(log n) per operation, not O(n)")
    func scalesLogarithmically() {
        let addresses = 65_536
        let attempts = 3
        var queue = ExpiryQueue<Int>()
        var operations = 0

        // Arm every first transmission, then expire and re-arm in waves, as a sweep
        // does: a probe is popped when due and, while it has attempts left, re-armed.
        for key in 0..<addresses {
            queue.schedule(key, at: at(key % 50))
            operations += 1
        }
        var transmissions = [Int](repeating: 1, count: addresses)
        var now = 0
        while !queue.isEmpty {
            now += 10
            while let key = queue.popFirst(dueBy: at(now)) {
                operations += 1
                if transmissions[key] < attempts {
                    transmissions[key] += 1
                    queue.schedule(key, at: at(now + 50))
                    operations += 1
                }
            }
            // A quarter of the outstanding hosts answer each wave and are cancelled.
            if now % 40 == 0 {
                for key in stride(from: now % 4, to: addresses, by: 4) where queue.contains(key) {
                    queue.cancel(key)
                    operations += 1
                }
            }
        }

        // log2(65,536 × 3) ≈ 17.6. A heap does at most ~2·log2(n) comparisons per
        // operation; the bound below allows that and nothing near the ~100,000 per
        // operation a linear scan of the outstanding set would cost.
        let perOperation = Double(queue.comparisons) / Double(operations)
        #expect(perOperation < 40, "\(queue.comparisons) comparisons over \(operations) operations")
    }
}

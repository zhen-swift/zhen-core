#!/bin/zsh
#
# verify-reach-testbed.sh — the 0.8.0 gates that need the study testbed, and some need root.
#
# JC runs this; an agent does not (it needs sudo, for `arp -a -d` before each cold run and
# for G9's root row). Every scan writes history to a scratch file under $OUT, never to the
# store in ~/Library — ZHEN_HISTORY is exported before anything runs, and passed through
# sudo explicitly where sudo is used.
#
# Usage:
#   swift build -c release
#   for v in netbed{1..5}; do limactl start $v; done          # the testbed, if stopped
#   Scripts/verify-reach-testbed.sh g3|g4|g5|g5w|g6|g7 <vm>|g8|g9|all
#
# Every gate prints its pass condition first, then one JSON line per run, then a verdict
# line it computed — read the lines, not only the verdict. Artifacts stay in $OUT.
#
#   G3  --reach learned --no-neighbor-watch: discovery within ±10% of study 1's warm
#       367 ms (330–404 ms, median of 10); cold misses only .12/.13.
#   G4  empty history, cold cache, default: every reference host in 10 of 10 runs.
#   G5  primed history (≥ 20 cold samples), cold cache, default: 10 of 10, and mean wall
#       clock below G4's.
#   G5w F1's warm path, after g5 with the same $OUT: G5 again with the cache left warm —
#       no address takes the first-scan wait, 10 of 10. Then Q8's case, a warm cache and
#       no history: the cold addresses take it and no warm address does (first_scan = cold).
#   G6  .11 (ARP-only) is neighbor_resolved cold and neighbor_table warm.
#   G7  a VM taken down and brought back: --look-longer finds its addresses, adds them to
#       the latest run, and nobody else is marked absent.  `g7 netbed3`
#   G8  change 8's testbed comparison: three --discovery-only runs, nothing moved.
#   G9  the study contract on the testbed, one scan per row, including `sudo zhen scan`.
#
# The reference host set is one warm scan with `--reach 3s` (every address waited for
# three seconds), taken once per $OUT and saved as reference.json. "Every host" in G4/G5
# and "misses" in G3 are against it.

set -u
REPO=${0:A:h:h}
Z=${ZHEN:-$REPO/.build/release/zhen}
CIDR=${CIDR:-192.168.64.0/24}
IFACE=${IFACE:-bridge100}
OUT=${OUT:-$(mktemp -d /tmp/zhen-reach.XXXXXX)}
export ZHEN_HISTORY=$OUT/history.ndjson

case ${1:-} in
  g3|g4|g5|g5w|g6|g7|g8|g9|all) ;;
  *) echo "usage: $0 g3|g4|g5|g5w|g6|g7 <vm>|g8|g9|all"; exit 64 ;;
esac
[[ -x $Z ]] || { echo "no binary at $Z — run 'swift build -c release' first"; exit 2; }
ifconfig $IFACE >/dev/null 2>&1 || { echo "no $IFACE — is the testbed up? (limactl start netbedN, one at a time)"; exit 2; }
echo "zhen:    $($Z --version)"
echo "out:     $OUT"
echo "history: $ZHEN_HISTORY (scratch)"

# A cold run that is secretly warm would pass G4 for the wrong reason, so a failed flush stops
# the script rather than being swallowed.
cold() { sudo arp -a -d >/dev/null || { echo "sudo arp -a -d failed — refusing to call a warm run cold"; exit 3 } }
scan() { $Z scan --cidr $CIDR --iface $IFACE --discovery-only --json --quiet "$@" }
# IPv4 addresses found, in numeric order, one line.
hosts() {
  jq -r '[.devices[].addresses[] | select(test("^[0-9]+(\\.[0-9]+){3}$"))]
         | sort_by(split(".") | map(tonumber)) | join(" ")' "$1"
}
summary() {
  jq -c '{discovery_ms: ([.run.timing.stages[] | select(.stage == "discovery") | .elapsed_millis][0] | floor),
          wall_ms: (.run.finished_at - .run.started_at),
          hosts: ([.devices[].addresses[] | select(test("^[0-9]+(\\.[0-9]+){3}$"))] | length),
          policy: .run.reach.policy, first_scan: .run.reach.first_scan,
          history_samples: .run.reach.history_samples, warm_samples: .run.reach.warm_samples,
          paths: .run.reach.paths, watch: .run.neighbor_watch.enabled,
          expected_missing: .run.reach.expected_missing}' "$1"
}
# Reference hosts that a run did not find.
missing() { comm -23 <(hosts $OUT/reference.json | tr ' ' '\n' | sort) <(hosts "$1" | tr ' ' '\n' | sort) | tr '\n' ' ' }
reference() {
  [[ -f $OUT/reference.json ]] && return
  ZHEN_HISTORY=$OUT/reference-history.ndjson scan --reach 3s > /dev/null      # warms the cache
  ZHEN_HISTORY=$OUT/reference-history.ndjson scan --reach 3s > $OUT/reference.json
  echo "reference ($(hosts $OUT/reference.json | wc -w | tr -d ' ') hosts): $(hosts $OUT/reference.json)"
}
# The study testbed is impaired: .11 answers ARP but not echo, .12/.13 are delayed, and each VM
# answers ARP only on its own interface. A rebooted testbed has none of that, and G3's cold half,
# G5 and G6 then measure nothing (seen 2026-10-15). Warn rather than refuse: the run still shows
# the mechanism.
preflight() {
  if ping -c 1 -t 1 ${IP11:-192.168.64.11} >/dev/null 2>&1; then
    echo "WARNING: .11 answers echo — the testbed is not in its study configuration; restore it, or read $1 as unjudgeable"
  fi
}
mean() { jq -s 'map(.run.finished_at - .run.started_at) | add / length | floor' "$@" }
median_discovery() {
  jq -s 'map([.run.timing.stages[] | select(.stage == "discovery") | .elapsed_millis][0]) | sort | .[length / 2 | floor]' "$@"
}

g3() {
  echo "\n== G3 — --reach learned --no-neighbor-watch. Pass: warm median 330–404 ms; cold misses only .12/.13."
  preflight G3; reference
  local flags=(--reach learned --no-neighbor-watch)
  rm -f $ZHEN_HISTORY; scan $flags > /dev/null
  for i in {1..10}; do scan $flags > $OUT/g3-warm-$i.json; summary $OUT/g3-warm-$i.json; done
  echo "G3 warm median discovery_ms: $(median_discovery $OUT/g3-warm-*.json)"
  for i in {1..10}; do
    cold; scan $flags > $OUT/g3-cold-$i.json
    echo "$(summary $OUT/g3-cold-$i.json) missed: [$(missing $OUT/g3-cold-$i.json)]"
  done
}

g4() {
  echo "\n== G4 — empty history, cold cache, default. Pass: missed is empty in 10 of 10."
  reference
  for i in {1..10}; do
    cold; scan --no-history > $OUT/g4-$i.json
    echo "$(summary $OUT/g4-$i.json) missed: [$(missing $OUT/g4-$i.json)]"
  done
  echo "G4 mean wall_ms: $(mean $OUT/g4-*.json)"
}

g5() {
  echo "\n== G5 — primed history, cold cache, default. Pass: 10 of 10, first_scan false, mean wall below G4's."
  preflight G5; reference
  rm -f $ZHEN_HISTORY
  # Prime: cold default scans into the scratch history until it holds 20 cold samples.
  local total=0
  for i in {1..12}; do
    cold; scan > $OUT/g5-prime-$i.json
    local n=$(jq '[.devices[] | select(.first_contact_cold == true)] | length' $OUT/g5-prime-$i.json)
    total=$((total + n))
    echo "prime $i: $(summary $OUT/g5-prime-$i.json) cold samples: +$n = $total"
    (( total >= 20 )) && break
  done
  for i in {1..10}; do
    cold; scan > $OUT/g5-$i.json
    echo "$(summary $OUT/g5-$i.json) missed: [$(missing $OUT/g5-$i.json)]"
  done
  echo "G5 mean wall_ms: $(mean $OUT/g5-[0-9]*.json)   (G4's: $(ls $OUT/g4-*.json >/dev/null 2>&1 && mean $OUT/g4-*.json || echo 'run g4 first'))"
}

g5w() {
  echo "\n== G5w — F1's warm path. Pass: after g5, warm cache, primed history: paths.first_scan 0 and missed empty in 10 of 10, paths.warm > 0; then warm cache, no history: paths.first_scan == paths.cold and paths.warm > 0 in 3 of 3."
  ls $OUT/g5-[0-9]*.json >/dev/null 2>&1 || { echo "run g5 first, with the same OUT=$OUT"; return 2 }
  reference
  # No flush anywhere in this gate: the cache is whatever the scan before left, which is warm.
  scan > /dev/null
  local ok=0
  for i in {1..10}; do
    scan > $OUT/g5w-$i.json
    echo "$(summary $OUT/g5w-$i.json) missed: [$(missing $OUT/g5w-$i.json)]"
    jq -e '.run.reach.paths | .first_scan == 0 and .warm > 0' $OUT/g5w-$i.json >/dev/null \
      && [[ -z $(missing $OUT/g5w-$i.json) ]] && ok=$((ok + 1))
  done
  echo "G5w primed: $ok of 10 with no first-scan wait, a warm cache and every reference host   mean wall_ms: $(mean $OUT/g5w-*.json) (G5's: $(mean $OUT/g5-[0-9]*.json))"
  # Q8's machine: it has only ever scanned warm, so it has no cold history. Every cold
  # (dead) address still takes the first-scan wait by the rule; a warm one never may.
  ok=0
  for i in 1 2 3; do
    scan --no-history > $OUT/g5w-empty-$i.json
    echo "empty $i: $(summary $OUT/g5w-empty-$i.json)"
    jq -e '.run.reach.paths | .first_scan == .cold and .warm > 0' $OUT/g5w-empty-$i.json >/dev/null && ok=$((ok + 1))
  done
  echo "G5w empty history: $ok of 3 where no warm address took the first-scan wait"
}

g6() {
  echo "\n== G6 — .11 is neighbor_resolved cold, neighbor_table warm."
  preflight G6
  local ip=${IP11:-192.168.64.11}
  cold; scan --no-history > $OUT/g6-cold.json
  scan --no-history > $OUT/g6-warm.json
  for run in cold warm; do
    echo "$run: $(jq -c --arg ip $ip '[.devices[] | select(.addresses | index($ip)) | {discovered_via, first_contact_millis, first_contact_cold, found_after_millis}]' $OUT/g6-$run.json) watch: $(jq -c '.run.neighbor_watch' $OUT/g6-$run.json)"
  done
}

g7() {
  local vm=${1:-}
  [[ -n $vm ]] || { echo "usage: $0 g7 <netbedN>"; return 2 }
  echo "\n== G7 — $vm down, then back; --look-longer. Pass: its addresses appear in the latest run; present count back to the baseline; one appeared per address, no new disappeared."
  rm -f $ZHEN_HISTORY
  scan > $OUT/g7-baseline.json
  local base=$($Z hosts --json | jq '[.devices[] | select(.present)] | length')
  echo "baseline: $(summary $OUT/g7-baseline.json) present in history: $base"
  limactl stop $vm
  # The NDP cache too: an entry for the VM's link-local outlives the VM by up to a day and
  # keeps its device present, so it never goes absent and look-longer has nothing to add (Q13).
  cold; sudo ndp -c >/dev/null; scan > $OUT/g7-down.json
  echo "down:     $(summary $OUT/g7-down.json)"
  local gone=$(comm -23 <(hosts $OUT/g7-baseline.json | tr ' ' '\n' | sort) <(hosts $OUT/g7-down.json | tr ' ' '\n' | sort) | tr '\n' ' ')
  echo "gone with $vm: [$gone]   expected_missing: $(jq -c '.run.reach.expected_missing' $OUT/g7-down.json)"
  local latest=$(jq -r '.run.id' $OUT/g7-down.json)
  limactl start $vm
  # --iface: look-longer takes the network from the latest run but not its interface (Q12).
  $Z scan --look-longer --reach 20s --iface $IFACE --json --quiet > $OUT/g7-look.json
  echo "look:     $(jq -c '{extends_run: .run.extends_run, found: [.devices[].addresses[0]], still_missing: .run.reach.expected_missing, reach: .run.reach.policy}' $OUT/g7-look.json)"
  echo "extends the latest run: $([[ $(jq -r '.run.extends_run' $OUT/g7-look.json) == $latest ]] && echo yes || echo NO)"
  echo "present in history now: $($Z hosts --json | jq '[.devices[] | select(.present)] | length') (baseline $base)"
  echo "events since the down scan: $($Z events --json | jq -c --arg run $latest '[.events[] | select(.run_id == $run) | .kind] | group_by(.) | map({(.[0]): length}) | add')"
}

g8() {
  echo "\n== G8 (testbed half) — three --discovery-only runs; nothing a sweep finds has moved."
  for i in 1 2 3; do scan --reach learned --no-neighbor-watch > $OUT/g8-$i.json
    jq -c '.run.timing.stages[0] | {elapsed_millis, probes_sent, hosts_found}' $OUT/g8-$i.json; done
}

g9() {
  echo "\n== G9 (JC half) — one scan per row of change 9's table; each flag's value must be in the artifact."
  rm -f $ZHEN_HISTORY
  echo "row 8, --version: $($Z --version)"
  scan --reach-percentile 0.9 --first-scan-wait 1200ms --reach-cap 4s --reach-min-samples 10 \
    --expected-attempts-step 400ms --expected-attempts-cap 7 > $OUT/g9-1.json
  echo "row 1: $(jq -c '.run.reach' $OUT/g9-1.json)"
  scan --reach learned --no-neighbor-watch > $OUT/g9-2.json
  echo "row 2: $(jq -c '{policy: .run.reach.policy, neighbor_watch: .run.neighbor_watch}' $OUT/g9-2.json)"
  local before=$(shasum -a 256 $ZHEN_HISTORY | cut -d' ' -f1)
  scan --no-history > $OUT/g9-3.json
  echo "row 3: $(jq -c '{first_scan: .run.reach.first_scan, history_samples: .run.reach.history_samples, history_read: .run.reach.history_read}' $OUT/g9-3.json) store unchanged: $([[ $before == $(shasum -a 256 $ZHEN_HISTORY | cut -d' ' -f1) ]] && echo yes || echo NO)"
  cold; scan > $OUT/g9-4.json
  echo "rows 4–6: $(jq -c '{stage: (.run.timing.stages[0] | {attempts, concurrency, retransmit_budget_millis, tail_budget_millis}), hosts: [.devices[] | {a: .addresses[0], via: .discovered_via, found_after_millis, first_contact_millis, first_contact_cold}]}' $OUT/g9-4.json)"
  sudo env ZHEN_HISTORY=$OUT/root-history.ndjson $Z scan --cidr $CIDR --iface $IFACE --discovery-only --json --quiet > $OUT/g9-7.json
  echo "row 7 (root): $(jq -c '{engine: .run.engine, tool: .run.tool, via: ([.devices[].discovered_via[]] | group_by(.) | map({(.[0]): length}) | add)}' $OUT/g9-7.json)"
  echo "row 8: $(jq -c '.run.tool' $OUT/g9-1.json)"
}

case ${1:-} in
  g3) g3 ;; g4) g4 ;; g5) g5 ;; g5w) g5w ;; g6) g6 ;; g7) g7 ${2:-} ;; g8) g8 ;; g9) g9 ;;
  all) g3; g4; g5; g5w; g6; g8; g9; echo "\n(G7 takes a VM down; run it on its own: $0 g7 netbed3)" ;;
  *) echo "usage: $0 g3|g4|g5|g5w|g6|g7 <vm>|g8|g9|all"; exit 64 ;;
esac

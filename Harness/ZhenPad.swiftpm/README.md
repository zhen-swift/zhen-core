# ZhenPad: the iPadOS harness

The smallest iPad app that runs the engine. It isn't a product and doesn't ship. It
depends on this checkout **by local path**, so it always runs the engine as it stands
here, with no release. `Docs/IPADOS.md` says what the iPadOS build is and why.

- **Probe tab.** Makes each syscall the iPadOS composition makes an assumption about:
  - the ICMP socket
  - the route and ARP sysctls
  - the descriptor limit
  - this device's MAC
  - an SSDP multicast send
  - the declared Bonjour types

  It marks anything that didn't behave as assumed, and shares the results as text.
- **Scan tab.** One scan through `ZhenScan.ScanRunner`, the Mac app's adapter. It shows
  the devices and degradations and shares the report as JSON. The screen stays on while
  it runs.
- **`-autorun`.** Runs both with no input, then writes `probe.txt`, `report.json` and
  finally `done` into the app's Documents directory.

## Simulator

```bash
cd Harness/ZhenPad.swiftpm
xcodebuild build -scheme ZhenPad -destination 'platform=iOS Simulator,name=iPad Pro 13-inch (M5)' \
  -derivedDataPath /tmp/zhenpad
xcrun simctl install booted /tmp/zhenpad/Build/Products/Debug-iphonesimulator/ZhenPad.app
xcrun simctl launch booted com.jctec.zhen.pad-harness -autorun
cat "$(xcrun simctl get_app_container booted com.jctec.zhen.pad-harness data)/Documents/probe.txt"
```

The simulator uses the Mac's kernel. Its probe results describe the Mac, not an iPad.

## Device

Open `Harness/ZhenPad.swiftpm` in Xcode, choose a signing team under Signing &
Capabilities, pick the iPad, and run. Accept the Local Network prompt for a normal run. To
see what a denial looks like, deny it once (or turn it off in Settings › Privacy &
Security › Local Network) and scan again.

Only run scans on a network you run.

// Locked's native helper for macOS. src/native.ts builds it into ~/.locked/LockedPanel.app.
//
//   LockedPanel --panel <url>    A floating banner in the top-right corner. Each field gets Type
//                                (types it into whatever input has focus) and Copy. The panel never
//                                takes focus, so the page's input stays focused while you click it.
//                                <url> is a one-time http://127.0.0.1:7411/api/panel/<token> handle;
//                                values are fetched from it only when you first click Type or Copy.
//   LockedPanel --auth <reason>  Touch ID (or the login password). Exit 0 when the owner confirmed,
//                                1 when they cancelled or failed, 2 when there's no way to ask.
//   LockedPanel --preview <png>  Renders the panel with sample data, to check the layout.
//
// It never prints values. Typing needs the Accessibility permission (System Settings → Privacy &
// Security → Accessibility → Locked); Copy works without it.

import AppKit
import LocalAuthentication

// MARK: - Touch ID

func runAuth(_ reason: String) -> Never {
  let context = LAContext()
  var error: NSError?
  guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else { exit(2) }
  let done = DispatchSemaphore(value: 0)
  var confirmed = false
  context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { ok, _ in
    confirmed = ok
    done.signal()
  }
  done.wait()
  exit(confirmed ? 0 : 1)
}

// MARK: - Talking to the Locked server

struct FieldInfo {
  let name: String
  let label: String
  let type: String
}

struct PanelInfo {
  let label: String
  let site: String?
  let purpose: String?
  let level: String
  let fields: [FieldInfo]
  let timeoutSec: Int
}

struct ApiError: Error {
  let message: String
}

final class Api {
  let base: URL
  let session: URLSession

  init(_ base: URL) {
    self.base = base
    let config = URLSessionConfiguration.ephemeral
    config.timeoutIntervalForRequest = 120 // a sealed value waits for Touch ID
    config.urlCache = nil
    session = URLSession(configuration: config)
  }

  func call(_ method: String, _ path: String, _ body: [String: Any]? = nil) async throws -> [String: Any] {
    var req = URLRequest(url: path.isEmpty ? base : base.appendingPathComponent(path))
    req.httpMethod = method
    if let body {
      req.setValue("application/json", forHTTPHeaderField: "Content-Type")
      req.httpBody = try JSONSerialization.data(withJSONObject: body)
    }
    let (data, _) = try await session.data(for: req)
    guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw ApiError(message: "bad response") }
    if json["ok"] as? Bool != true { throw ApiError(message: json["error"] as? String ?? "failed") }
    return json
  }

  func info() async throws -> PanelInfo {
    let j = try await call("GET", "")
    let fields = (j["fields"] as? [[String: Any]] ?? []).map {
      FieldInfo(name: $0["name"] as? String ?? "", label: $0["label"] as? String ?? "", type: $0["type"] as? String ?? "text")
    }
    return PanelInfo(
      label: j["label"] as? String ?? "Secret",
      site: j["site"] as? String,
      purpose: j["purpose"] as? String,
      level: j["level"] as? String ?? "normal",
      fields: fields,
      timeoutSec: j["timeoutSec"] as? Int ?? 120
    )
  }

  func values() async throws -> [String: String] {
    let j = try await call("POST", "values", [:])
    return j["values"] as? [String: String] ?? [:]
  }

  /// Fire and forget: the server audits these and wakes `locked panel`.
  func event(_ event: String, _ field: String? = nil) {
    var body: [String: Any] = ["event": event]
    if let field { body["field"] = field }
    Task { _ = try? await call("POST", "event", body) }
  }
}

// MARK: - Typing and the clipboard

func typeText(_ text: String) {
  let source = CGEventSource(stateID: .combinedSessionState)
  for ch in text {
    var units = Array(String(ch).utf16)
    for down in [true, false] {
      guard let e = CGEvent(keyboardEventSource: source, virtualKey: 0, keyDown: down) else { continue }
      e.flags = []
      e.keyboardSetUnicodeString(stringLength: units.count, unicodeString: &units)
      e.post(tap: .cghidEventTap)
    }
    usleep(6_000)
  }
}

func pressTab() {
  let source = CGEventSource(stateID: .combinedSessionState)
  for down in [true, false] {
    guard let e = CGEvent(keyboardEventSource: source, virtualKey: 48, keyDown: down) else { continue }
    e.flags = []
    e.post(tap: .cghidEventTap)
  }
  usleep(30_000)
}

func canType(prompt: Bool) -> Bool {
  if AXIsProcessTrusted() { return true }
  if prompt {
    let key = kAXTrustedCheckOptionPrompt.takeUnretainedValue() as String
    _ = AXIsProcessTrustedWithOptions([key: true] as CFDictionary)
  }
  return false
}

let concealed = NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")
let transient = NSPasteboard.PasteboardType("org.nspasteboard.TransientType")

// MARK: - The panel

/// Never key or main, so clicks on it leave the focused input on the page alone.
final class Panel: NSPanel {
  override var canBecomeKey: Bool { false }
  override var canBecomeMain: Bool { false }
}

/// Reacts to the first click even though the panel's app isn't active.
final class Button: NSButton {
  var onClick: (() -> Void)?
  override func acceptsFirstMouse(for event: NSEvent?) -> Bool { true }
  @objc func fire() { onClick?() }
}

func button(_ title: String, symbol: String? = nil, _ action: @escaping () -> Void) -> Button {
  let b = Button(title: title, target: nil, action: nil)
  b.target = b
  b.action = #selector(Button.fire)
  b.onClick = action
  b.bezelStyle = .rounded
  b.controlSize = .small
  if let symbol, let image = NSImage(systemSymbolName: symbol, accessibilityDescription: title) {
    b.image = image
    b.imagePosition = .imageLeading
  }
  return b
}

/// The panel's inner width: 360 minus 14 points of padding on each side.
let innerWidth: CGFloat = 332

func label(_ text: String, size: CGFloat = 12, weight: NSFont.Weight = .regular, color: NSColor = .labelColor, wraps: Bool = false) -> NSTextField {
  let l = wraps ? NSTextField(wrappingLabelWithString: text) : NSTextField(labelWithString: text)
  l.font = .systemFont(ofSize: size, weight: weight)
  l.textColor = color
  if wraps {
    l.preferredMaxLayoutWidth = innerWidth
    l.widthAnchor.constraint(equalToConstant: innerWidth).isActive = true
  } else {
    l.lineBreakMode = .byTruncatingTail
  }
  return l
}

final class Controller {
  let api: Api
  let info: PanelInfo
  let panel: Panel
  let status = label("", size: 11, color: .secondaryLabelColor, wraps: true)
  let countdown = label("", size: 11, color: .secondaryLabelColor)
  var values: [String: String]?
  var busy = false
  var closed = false
  var pendingClears = 0
  var deadline: Date

  init(api: Api, info: PanelInfo) {
    self.api = api
    self.info = info
    deadline = Date().addingTimeInterval(TimeInterval(info.timeoutSec))
    panel = Panel(contentRect: NSRect(x: 0, y: 0, width: 360, height: 10), styleMask: [.nonactivatingPanel, .borderless], backing: .buffered, defer: false)
    panel.level = .statusBar
    panel.isFloatingPanel = true
    panel.hidesOnDeactivate = false
    panel.isMovableByWindowBackground = true
    panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .stationary]
    panel.backgroundColor = .clear
    panel.isOpaque = false
    panel.hasShadow = true
    build()
  }

  func build() {
    let effect = NSVisualEffectView()
    effect.material = .popover
    effect.state = .active
    effect.wantsLayer = true
    effect.layer?.cornerRadius = 14
    effect.layer?.masksToBounds = true

    let stack = NSStackView()
    stack.orientation = .vertical
    stack.alignment = .leading
    stack.spacing = 8
    stack.edgeInsets = NSEdgeInsets(top: 12, left: 14, bottom: 12, right: 14)
    stack.translatesAutoresizingMaskIntoConstraints = false

    // Header: lock, title, time left, close.
    let lock = NSImageView(image: NSImage(systemSymbolName: info.level == "sealed" ? "lock.shield.fill" : "lock.fill", accessibilityDescription: "Locked")!)
    lock.contentTintColor = .systemGreen
    let title = label("Locked · \(info.label)", size: 13, weight: .semibold)
    let close = button("", symbol: "xmark") { [weak self] in self?.finish("closed") }
    close.isBordered = false
    title.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
    countdown.font = .monospacedDigitSystemFont(ofSize: 11, weight: .regular)
    let header = NSStackView(views: [lock, title, NSView(), countdown, close])
    header.orientation = .horizontal
    header.spacing = 6
    stack.addArrangedSubview(header)
    header.widthAnchor.constraint(equalTo: stack.widthAnchor, constant: -28).isActive = true

    var sub: [String] = []
    if let site = info.site { sub.append(site) }
    if let purpose = info.purpose, !purpose.isEmpty { sub.append("Agent: \(purpose)") }
    if info.level == "sealed" { sub.append("Sealed: Touch ID before the first use") }
    if !sub.isEmpty { stack.addArrangedSubview(label(sub.joined(separator: " · "), size: 11, color: .secondaryLabelColor, wraps: true)) }

    for field in info.fields {
      let name = label(field.label.isEmpty ? field.name : field.label, size: 12, weight: .medium)
      name.widthAnchor.constraint(equalToConstant: 96).isActive = true
      let dots = label("••••••••", size: 12, color: .tertiaryLabelColor)
      let type = button("Type", symbol: "keyboard") { [weak self] in self?.type([field.name]) }
      let copy = button("Copy", symbol: "doc.on.doc") { [weak self] in self?.copy(field.name) }
      let row = NSStackView(views: [name, dots, NSView(), type, copy])
      row.orientation = .horizontal
      row.spacing = 6
      stack.addArrangedSubview(row)
      row.widthAnchor.constraint(equalTo: stack.widthAnchor, constant: -28).isActive = true
    }

    if info.fields.count > 1 {
      let all = button("Type all (Tab between)", symbol: "keyboard.badge.ellipsis") { [weak self] in
        guard let self else { return }
        self.type(self.info.fields.map(\.name))
      }
      stack.addArrangedSubview(all)
    }

    status.stringValue = "Click the input on the page, then Type. Or Copy and paste it."
    stack.addArrangedSubview(status)

    effect.addSubview(stack)
    NSLayoutConstraint.activate([
      stack.leadingAnchor.constraint(equalTo: effect.leadingAnchor),
      stack.trailingAnchor.constraint(equalTo: effect.trailingAnchor),
      stack.topAnchor.constraint(equalTo: effect.topAnchor),
      stack.bottomAnchor.constraint(equalTo: effect.bottomAnchor),
      stack.widthAnchor.constraint(equalToConstant: 360),
    ])
    panel.contentView = effect
    panel.setContentSize(stack.fittingSize)
  }

  func show() {
    let screen = NSScreen.main ?? NSScreen.screens[0]
    let frame = screen.visibleFrame
    panel.setFrameOrigin(NSPoint(x: frame.maxX - panel.frame.width - 16, y: frame.maxY - panel.frame.height - 12))
    panel.orderFrontRegardless()
    tick()
    Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in self?.tick() }
  }

  func tick() {
    let left = Int(deadline.timeIntervalSinceNow.rounded())
    if left <= 0 { return finish("expired") }
    countdown.stringValue = String(format: "%d:%02d", left / 60, left % 60)
  }

  func say(_ text: String) {
    status.stringValue = text
    // Grow or shrink to fit the message, keeping the top edge where it is.
    guard let view = panel.contentView else { return }
    view.layoutSubtreeIfNeeded()
    let top = panel.frame.maxY
    panel.setContentSize(view.fittingSize)
    panel.setFrameOrigin(NSPoint(x: panel.frame.minX, y: top - panel.frame.height))
  }

  /// Values arrive on first use (for a sealed secret, after Touch ID), then stay in memory until the panel closes.
  func withValues(_ use: @escaping ([String: String]) -> Void) {
    if let values { return use(values) }
    if busy { return }
    busy = true
    say(info.level == "sealed" ? "Confirm with Touch ID…" : "Getting it…")
    Task { @MainActor in
      defer { self.busy = false }
      do {
        let v = try await self.api.values()
        if self.closed { return }
        self.values = v
        use(v)
      } catch let e as ApiError {
        self.say(e.message)
      } catch {
        self.say("Locked isn't answering.")
      }
    }
  }

  func type(_ names: [String]) {
    guard canType(prompt: true) else {
      say("To type, allow Locked in System Settings → Privacy & Security → Accessibility. Copy works now.")
      api.event("needs_accessibility")
      return
    }
    withValues { [weak self] values in
      guard let self else { return }
      // Let the click finish so modifiers and focus settle before the keystrokes.
      DispatchQueue.main.asyncAfter(deadline: .now() + 0.12) {
        for (i, name) in names.enumerated() {
          if i > 0 { pressTab() }
          typeText(values[name] ?? "")
          self.api.event("typed", name)
        }
        self.say(names.count == 1 ? "Typed \(self.fieldLabel(names[0]))." : "Typed \(names.count) fields.")
      }
    }
  }

  func copy(_ name: String) {
    withValues { [weak self] values in
      guard let self else { return }
      let pb = NSPasteboard.general
      pb.clearContents()
      let item = NSPasteboardItem()
      item.setString(values[name] ?? "", forType: .string)
      item.setData(Data(), forType: concealed)
      item.setData(Data(), forType: transient)
      pb.writeObjects([item])
      let count = pb.changeCount
      self.pendingClears += 1
      self.api.event("copied", name)
      self.say("Copied \(self.fieldLabel(name)); the clipboard clears in 30 s.")
      DispatchQueue.main.asyncAfter(deadline: .now() + 30) {
        if pb.changeCount == count { pb.clearContents() }
        self.pendingClears -= 1
        self.exitWhenIdle()
      }
    }
  }

  func fieldLabel(_ name: String) -> String {
    info.fields.first { $0.name == name }.map { $0.label.isEmpty ? $0.name : $0.label.lowercased() } ?? name
  }

  func finish(_ why: String) {
    if closed { return }
    closed = true
    values = nil
    panel.orderOut(nil)
    api.event(why)
    // Give the last event a moment to reach the server.
    DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { self.exitWhenIdle() }
  }

  func exitWhenIdle() {
    if closed && pendingClears == 0 { exit(0) }
  }
}

// MARK: - Entry

/// `--preview <out.png> [sealed]`: renders the panel with sample data to a PNG, for checking the
/// layout without a server or screen-recording permission. Never touches a real secret.
func runPreview(_ path: String, sealed: Bool) -> Never {
  _ = NSApplication.shared
  let info = PanelInfo(
    label: "GitHub login", site: "https://github.com", purpose: "sign in to merge PR #42", level: sealed ? "sealed" : "normal",
    fields: [FieldInfo(name: "username", label: "Username", type: "username"), FieldInfo(name: "password", label: "Password", type: "password")],
    timeoutSec: 120
  )
  let c = Controller(api: Api(URL(string: "http://127.0.0.1:1/api/panel/preview")!), info: info)
  c.countdown.stringValue = "2:00"
  let view = c.panel.contentView!
  view.layoutSubtreeIfNeeded()
  // The blur doesn't render off screen, so paint a plain backdrop under it.
  let rep = view.bitmapImageRepForCachingDisplay(in: view.bounds)!
  NSGraphicsContext.saveGraphicsState()
  NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
  NSColor.windowBackgroundColor.setFill()
  NSBezierPath(roundedRect: view.bounds, xRadius: 14, yRadius: 14).fill()
  NSGraphicsContext.restoreGraphicsState()
  view.cacheDisplay(in: view.bounds, to: rep)
  try? rep.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: path))
  exit(0)
}

let argv = CommandLine.arguments
if argv.count >= 3 && argv[1] == "--auth" { runAuth(argv[2]) }
if argv.count >= 3 && argv[1] == "--preview" { runPreview(argv[2], sealed: argv.count > 3 && argv[3] == "sealed") }
guard argv.count >= 3, argv[1] == "--panel", let url = URL(string: argv[2]), url.host == "127.0.0.1" || url.host == "localhost" else {
  FileHandle.standardError.write("usage: LockedPanel --panel <http://127.0.0.1:…/api/panel/…> | --auth <reason>\n".data(using: .utf8)!)
  exit(64)
}

let app = NSApplication.shared
app.setActivationPolicy(.accessory)
let api = Api(url)
var controller: Controller?
Task { @MainActor in
  do {
    let info = try await api.info()
    controller = Controller(api: api, info: info)
    controller?.show()
  } catch {
    FileHandle.standardError.write("LockedPanel: \(error)\n".data(using: .utf8)!)
    exit(1)
  }
}
app.run()

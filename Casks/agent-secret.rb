cask "agent-secret" do
  version "0.0.20"
  sha256 "49a5f950e538386bb13548b865e3f26663794f62f3508bc7f220a562bcaf16d6"

  url "https://github.com/kovyrin/agent-secret/releases/download/v#{version}/Agent-Secret-v#{version}-macos-arm64.dmg"
  name "Agent Secret"
  desc "Local approval broker for coding-agent secrets"
  homepage "https://github.com/kovyrin/agent-secret"

  livecheck do
    url :url
    strategy :github_latest
  end

  depends_on arch: :arm64
  depends_on macos: :sonoma

  app "Agent Secret.app"
  binary "#{appdir}/Agent Secret.app/Contents/Resources/bin/agent-secret"

  uninstall quit: [
    "com.kovyrin.agent-secret",
    "com.kovyrin.agent-secret.daemon",
  ]

  zap trash: [
    "~/.agents/skills/agent-secret",
    "~/Library/Application Support/agent-secret",
    "~/Library/Logs/agent-secret",
  ]

  caveats <<~EOS
    To install the bundled Codex skill:
      agent-secret skill-install

    Verify setup:
      agent-secret doctor
  EOS
end

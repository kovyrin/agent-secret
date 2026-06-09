cask "agent-secret" do
  version "0.0.19"
  sha256 "84ff5df3b4d7e06430b2f2be4a6e349fc6dfe7ddb22b5879bd027cc4a909839c"

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

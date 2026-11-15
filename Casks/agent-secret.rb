# frozen_string_literal: true

cask "agent-secret" do
  version "0.0.34"
  sha256 "4d3ed7aea0f378a2c8e30741a83932c817dd452031d014c5fff39d5263973fb5"

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

  postflight do
    system_command "#{appdir}/Agent Secret.app/Contents/Resources/bin/agent-secret",
                   args: ["install-cli", "--force"]
  end

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

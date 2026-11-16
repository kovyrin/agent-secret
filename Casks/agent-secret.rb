# frozen_string_literal: true

require "tempfile"

cask "agent-secret" do
  version "0.1.0"
  sha256 "fc4de36ae6b6e38a108f8dd5f01d7fdd87af86bc86041fce35fd9a40d9ce949f"

  url "https://github.com/kovyrin/agent-secret/releases/download/v#{version}/Agent-Secret-v#{version}-macos-arm64.dmg"
  name "Agent Secret"
  desc "Local approval broker for coding-agent secrets"
  homepage "https://github.com/kovyrin/agent-secret"
  auto_updates true

  livecheck do
    url :url
    strategy :github_latest
  end

  depends_on arch: :arm64
  depends_on macos: :sonoma

  acquire_installation = lambda do |directory|
    parent = File.realpath(directory)
    held = Thread.current.thread_variable_get(:agent_secret_installation)
    if held
      raise "Agent Secret installation directory changed during the transaction." unless held.fetch(:path) == parent

      next held
    end

    host = File.join(parent, "Agent Secret.app")
    updater = File.join(host, "Contents/Library/LoginItems/AgentSecretUpdater.app/Contents/MacOS/agent-secret-updater")
    requirement = '=anchor apple generic and certificate leaf[subject.OU] = "B6L7QLWTZW" and identifier "com.kovyrin.agent-secret"'
    original = File.lstat(host) if File.exist?(host) || File.symlink?(host)
    original_at_install_path = lambda do
      installed = File.lstat(host)
      original && installed.dev == original.dev && installed.ino == original.ino
    rescue Errno::ENOENT
      original.nil?
    end
    if File.executable?(updater)
      unless system("/usr/bin/codesign", "--verify", "--deep", "--strict", "-R", requirement, host)
        raise "Agent Secret failed signature verification. Reinstall the signed app before trying again."
      end
      unless system(updater, "--quiesce-for-package-manager")
        raise "Agent Secret still has work, live sessions, or another running copy. Wait for it to finish and retry."
      end
    end
    lease = File.open(parent)
    locked = 20.times.any? do
      next true if lease.flock(File::LOCK_EX | File::LOCK_NB)

      sleep 0.05
      false
    end
    unless locked
      lease.close
      raise "Agent Secret is in use or being updated. Wait for it to finish and retry."
    end
    unless original_at_install_path.call
      lease.close
      raise "Agent Secret changed while starting the transaction. Retry the command."
    end
    marker = File.join(parent, ".agent-secret-update")
    boot = IO.popen(["/usr/sbin/sysctl", "-n", "kern.bootsessionuuid"], &:read).strip
    unless boot.match?(/\A[0-9a-fA-F-]{36}\z/)
      lease.close
      raise "Could not identify the macOS boot session."
    end
    begin
      Tempfile.create(".agent-secret-update-", parent) do |file|
        file.chmod(0o644)
        file.write(%({"version":"","boot":"#{boot}"}))
        file.fsync
        File.link(file.path, marker)
      end
      lease.fsync
    rescue Errno::EEXIST
      lease.close
      raise "An Agent Secret installation needs recovery. Open Check for Updates, then retry."
    end
    transaction = { path: parent, lease: lease, restore_updater: false, uninstalling: false }
    Thread.current.thread_variable_set(:agent_secret_installation, transaction)
    # Keep ownership across old and new cask callbacks and any Homebrew rollback.
    at_exit do
      completed = $!.nil? || ($!.is_a?(SystemExit) && $!.success?)
      restored_original = false
      if !completed && transaction[:restore_updater] && original
        begin
          restored_original = original_at_install_path.call &&
                              system("/usr/bin/codesign", "--verify", "--deep", "--strict", "-R", requirement, host)
        rescue SystemCallError
          # Leave registration alone if the signed original is missing.
        end
      end
      # A failed exit cannot rule out a surviving installer child.
      if completed
        if transaction[:uninstalling] && !File.exist?(host) && !File.symlink?(host)
          {
            ".local/bin/agent-secret" => "Contents/Resources/bin/agent-secret",
            ".agents/skills/agent-secret" => "Contents/Resources/skills/agent-secret",
          }.each do |link, target|
            path = File.join(Dir.home, link)
            File.unlink(path) if File.symlink?(path) && File.readlink(path) == File.join(host, target)
          rescue Errno::ENOENT
            next
          rescue SystemCallError => e
            warn "Could not remove the Agent Secret link at #{path}: #{e.message}"
          end
        end
        File.unlink(marker)
        lease.fsync
      end
      lease.close
      host_executable = File.join(host, "Contents/MacOS/Agent Secret")
      if (completed || restored_original) && transaction[:restore_updater] && File.executable?(updater)
        system(host_executable, "--restore-background-updater")
      end
    end
    transaction
  end

  preflight do
    acquire_installation.call(appdir)
  end

  app "Agent Secret.app"
  binary "#{appdir}/Agent Secret.app/Contents/Resources/bin/agent-secret"

  postflight do
    transaction = acquire_installation.call(appdir)
    host = File.join(transaction.fetch(:path), "Agent Secret.app")
    cli = File.join(host, "Contents/Resources/bin/agent-secret")
    updater = File.join(host, "Contents/Library/LoginItems/AgentSecretUpdater.app")
    if File.directory?(updater)
      unless system(cli, "__agent-secret-cask-postflight", 3 => transaction.fetch(:lease))
        raise "Could not install the Agent Secret CLI link."
      end
    else
      system_command cli, args: ["install-cli", "--force"]
    end
  end

  uninstall_preflight do
    transaction = acquire_installation.call(appdir)
    transaction[:uninstalling] = true
    host = File.join(transaction.fetch(:path), "Agent Secret.app")
    if File.directory?(File.join(host, "Contents/Library/LoginItems/AgentSecretUpdater.app"))
      app = File.join(host, "Contents/MacOS/Agent Secret")
      status = IO.popen([app, "--suspend-background-updater"], &:read).strip
      raise "Could not unregister the Agent Secret background updater." unless $?.success?

      transaction[:restore_updater] ||= status == "enabled"
    end
  end

  uninstall quit: [
    "com.kovyrin.agent-secret",
    "com.kovyrin.agent-secret.daemon",
    "com.kovyrin.agent-secret.updater",
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

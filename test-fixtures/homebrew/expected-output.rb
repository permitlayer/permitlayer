# Homebrew formula for agentsso, the permitlayer daemon binary.
class Agentsso < Formula
  desc "agentsso binary: axum server, CLI, lifecycle management"
  homepage "https://github.com/permitlayer/permitlayer"
  version "0.2.1"
  if OS.mac?
    if Hardware::CPU.arm?
      url "https://github.com/permitlayer/permitlayer/releases/download/v0.2.1/permitlayer-daemon-aarch64-apple-darwin.tar.xz"
      sha256 "72b7400c5dd0bf925d55b71dce60eda04d3cc54392b5a3f18e65af189f41107e"
    end
    if Hardware::CPU.intel?
      url "https://github.com/permitlayer/permitlayer/releases/download/v0.2.1/permitlayer-daemon-x86_64-apple-darwin.tar.xz"
      sha256 "4ffd432ea95106fe6fab25ea10bcc04316cabcdbd02252546a6f42d6df9890ae"
    end
  end
  license "MIT"

  BINARY_ALIASES = {
    "aarch64-apple-darwin": {},
    "x86_64-apple-darwin": {}
  }

  def target_triple
    cpu = Hardware::CPU.arm? ? "aarch64" : "x86_64"
    os = OS.mac? ? "apple-darwin" : "unknown-linux-gnu"

    "#{cpu}-#{os}"
  end

  def install_binary_aliases!
    BINARY_ALIASES[target_triple.to_sym].each do |source, dests|
      dests.each do |dest|
        bin.install_symlink bin/source.to_s => dest
      end
    end
  end

  def install
    if OS.mac? && Hardware::CPU.arm?
      bin.install "agentsso"
    end
    if OS.mac? && Hardware::CPU.intel?
      bin.install "agentsso"
    end

    install_binary_aliases!

    # Homebrew will automatically install these, so we don't need to do that
    doc_files = Dir["README.*", "readme.*", "LICENSE", "LICENSE.*", "CHANGELOG.*"]
    leftover_contents = Dir["*"] - doc_files

    # Install any leftover files in pkgshare; these are probably config or
    # sample files.
    pkgshare.install(*leftover_contents) unless leftover_contents.empty?
  end

  def caveats
    <<~EOS
      permitlayer is installed. To get started:

          1. Create a Desktop OAuth client at
             https://console.cloud.google.com/apis/credentials and
             download the JSON ("client_secret_XXXX.json").
          2. Run setup, pointing at that JSON:

                 agentsso setup gmail --oauth-client ./client_secret.json

             For SSH-from-another-machine, add --headless. The bare
             `agentsso setup gmail` will interactively prompt for the
             file path if you forget the flag.

      To run the daemon as a Homebrew-managed background service:

          brew services start agentsso

      If `agentsso` is already running (you started it manually with
      `agentsso start`), stop it first with `agentsso stop` — `brew
      services start` cannot take over a port already bound by another
      process. Always verify the result with `brew services list`.

      Or start it yourself:

          agentsso start

      Enable login-autostart instead (separate from brew services):

          agentsso autostart enable

      Docs: https://github.com/permitlayer/permitlayer
    EOS
  end

  service do
    run [opt_bin/"agentsso", "start"]
    # Restart only on real crashes (signal-killed: SIGSEGV, SIGABRT,
    # OOM-kill, etc.). Don't respawn on deliberate non-zero exits like
    # `agentsso start`'s exit-3 when it detects an already-running
    # daemon — that's a configuration conflict, not a crash, and
    # respawn-looping it just produces noisy launchd `error 78` rows
    # in `brew services list` without resolving the conflict.
    keep_alive crashed: true
    log_path var/"log/agentsso.log"
    error_log_path var/"log/agentsso.log"
    working_dir HOMEBREW_PREFIX
  end
end

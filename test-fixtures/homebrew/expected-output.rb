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

      1. Set up the system service (one-time, per machine):

             sudo agentsso service install

         macOS will display a "Background item added" notification. If
         the daemon doesn't appear running, check
         System Settings → General → Login Items → Allow in the Background.

      2. From your end-user account, register an agent and mint a
         bearer token:

             agentsso agent register <name> --policy <policy-name>

         The token is written to ~/.agentsso/agent-bearer.token and is
         the credential your MCP client (OpenClaw / Claude Desktop /
         Cursor) authenticates with.

      3. Connect a service. Create a Desktop OAuth client at
         https://console.cloud.google.com/apis/credentials, download
         the JSON, and run:

             agentsso connect gmail --oauth-client ./client_secret.json --agent <name>

         For SSH-from-another-machine, add --headless.

      Verify the daemon is up:

          agentsso service status

      Daemon logs:

          /Library/Logs/permitlayer/daemon.log

      Docs: https://github.com/permitlayer/permitlayer
    EOS
  end
end

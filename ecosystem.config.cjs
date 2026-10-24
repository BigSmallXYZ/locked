// pm2 apps for Locked: the two local listeners, and the cloudflared tunnel to locked.flypack.app.
//   pm2 start ecosystem.config.cjs && pm2 save
const path = require("path");
const os = require("os");

module.exports = {
  apps: [
    {
      name: "locked",
      cwd: __dirname,
      script: path.join(os.homedir(), ".bun/bin/bun"),
      args: ["src/cli.ts", "serve"],
      interpreter: "none",
      autorestart: true,
      restart_delay: 2000,
      kill_timeout: 5000,
    },
    {
      name: "locked-tunnel",
      script: "/opt/homebrew/bin/cloudflared",
      args: ["tunnel", "--no-autoupdate", "--config", path.join(os.homedir(), ".cloudflared/locked.yml"), "run"],
      interpreter: "none",
      autorestart: true,
      restart_delay: 2000,
    },
  ],
};

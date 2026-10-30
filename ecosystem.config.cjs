// pm2 app for Locked: both local listeners, plus the tunnel from `locked tunnel use …`.
//   pm2 start ecosystem.config.cjs && pm2 save
module.exports = {
  apps: [
    {
      name: "locked",
      cwd: __dirname,
      script: "src/cli.ts",
      args: ["serve"],
      interpreter: "bun",
      autorestart: true,
      restart_delay: 2000,
      kill_timeout: 5000,
    },
  ],
};

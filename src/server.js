const app = require('./app');
const connectDB = require('./config/db');
const { port, nodeEnv } = require('./config/env');

let server;

(async () => {
  try {
    await connectDB();
    server = app.listen(port, () => {
      // eslint-disable-next-line no-console
      console.log(`Server running in ${nodeEnv} mode on http://localhost:${port}`);
    });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to start:', err.message);
    process.exit(1);
  }
})();

function shutdown(reason, err) {
  // eslint-disable-next-line no-console
  console.error(`${reason}:`, err?.message || err);
  if (server) server.close(() => process.exit(1));
  else process.exit(1);
}

process.on('unhandledRejection', (err) => shutdown('Unhandled rejection', err));
process.on('uncaughtException', (err) => shutdown('Uncaught exception', err));
process.on('SIGTERM', () => server && server.close(() => process.exit(0)));

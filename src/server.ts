import app from './app';
import { ENV } from './config/env';
import { connectDB } from './config/database';
import { logger } from './utils/logger';

const startServer = async () => {
  try {
    // Connect to database
    await connectDB();

    // Start HTTP server
    const server = app.listen(ENV.PORT, () => {
      logger.info(`🚀 Server ready at http://localhost:${ENV.PORT}`);
      logger.info(`🏥 Health check at http://localhost:${ENV.PORT}/health`);
    });

    // Graceful shutdown
    process.on('SIGTERM', () => {
      logger.info('SIGTERM received, shutting down gracefully');
      server.close(() => {
        logger.info('Process terminated');
        process.exit(0);
      });
    });

  } catch (error) {
    logger.error('Failed to start server:', error);
    process.exit(1);
  }
};

startServer();
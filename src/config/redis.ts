import { RedisOptions } from 'ioredis';

const getRedisConfig = (): RedisOptions => {
  // Production: Use Render's REDIS_URL if it exists
  if (process.env.REDIS_URL) {
    const url = new URL(process.env.REDIS_URL);
    return {
      host: url.hostname,
      port: parseInt(url.port, 10),
      password: url.password || undefined,
      tls: url.protocol === 'rediss:' ? {} : undefined, // Crucial for cloud Redis
      maxRetriesPerRequest: null
    };
  }

  // Local/Fallback: Use your existing split configuration
  return {
    host: process.env.REDIS_HOST || '127.0.0.1',
    port: parseInt(process.env.REDIS_PORT || '6379'),
    password: process.env.REDIS_PASSWORD || undefined,
    maxRetriesPerRequest: null
  };
};

export const redisConnection: RedisOptions = getRedisConfig();

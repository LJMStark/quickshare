/**
 * 应用配置文件
 * 根据不同环境加载不同的配置
 */

// 加载 .env 文件中的环境变量（如果存在）
try {
  require('dotenv').config();
} catch (e) {
  console.log('未找到 dotenv 模块或 .env 文件，使用默认环境变量');
}

const env = process.env.NODE_ENV || 'development';

const config = {
  // 开发环境配置
  development: {
    port: process.env.PORT || 5678,
    logLevel: 'dev',
    authEnabled: process.env.AUTH_ENABLED === 'true',
    authPassword: process.env.AUTH_PASSWORD,
    sessionSecret: process.env.SESSION_SECRET || 'dev-session-secret',
    sessionTtl: parseInt(process.env.SESSION_TTL || '86400', 10),
    rateLimit: {
      windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10),
      max: parseInt(process.env.RATE_LIMIT_MAX || '30', 10)
    }
  },

  // 生产环境配置
  production: {
    port: process.env.PORT || 8888,
    logLevel: 'combined',
    authEnabled: process.env.AUTH_ENABLED === 'true',
    authPassword: process.env.AUTH_PASSWORD,
    sessionSecret: process.env.SESSION_SECRET,
    sessionTtl: parseInt(process.env.SESSION_TTL || '86400', 10),
    rateLimit: {
      windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10),
      max: parseInt(process.env.RATE_LIMIT_MAX || '20', 10)
    }
  },

  // 测试环境配置
  test: {
    port: process.env.PORT || 3000,
    logLevel: 'dev',
    authEnabled: process.env.AUTH_ENABLED === 'true',
    authPassword: process.env.AUTH_PASSWORD,
    sessionSecret: process.env.SESSION_SECRET || 'test-secret',
    sessionTtl: parseInt(process.env.SESSION_TTL || '3600', 10),
    rateLimit: {
      windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10),
      max: parseInt(process.env.RATE_LIMIT_MAX || '100', 10)
    }
  }
};

// 导出当前环境的配置
module.exports = config[env] || config.development;

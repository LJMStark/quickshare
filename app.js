// 加载环境变量
require('dotenv').config();

const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const morgan = require('morgan');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const FileStore = require('session-file-store')(session);
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const Joi = require('joi');
const bcrypt = require('bcrypt');
const fs = require('fs');
const { initDatabase } = require('./models/db');

// 添加调试日志
console.log('应用启动...');
console.log('当前工作目录:', process.cwd());
console.log('环境变量:', {
  NODE_ENV: process.env.NODE_ENV,
  AUTH_ENABLED: process.env.AUTH_ENABLED
});

// 导入认证中间件
const { isAuthenticated } = require('./middleware/auth');

// 导入配置
const config = require('./config');

const authRateLimiter = rateLimit({
  windowMs: config.rateLimit.windowMs,
  max: config.rateLimit.max,
  standardHeaders: true,
  legacyHeaders: false
});

const passwordAttemptLimiter = rateLimit({
  windowMs: config.rateLimit.windowMs,
  max: Math.max(5, Math.floor(config.rateLimit.max / 2)),
  standardHeaders: true,
  legacyHeaders: false
});

// 路由导入
const pagesRoutes = require('./routes/pages');

// 初始化应用
const app = express();
// 确保在服务器上使用正确的端口
const PORT = process.env.NODE_ENV === 'production' ? 8888 : config.port;

// 将配置添加到应用本地变量中，便于在中间件中访问
app.locals.config = config;

// 中间件设置
app.use(morgan(config.logLevel));
app.use(cors());
app.use(helmet({ contentSecurityPolicy: false }));
app.use(bodyParser.json({ limit: '15mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '15mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// 创建会话目录
const sessionDir = path.join(__dirname, 'sessions');
console.log('会话目录:', sessionDir);
if (!fs.existsSync(sessionDir)) {
  console.log('创建会话目录...');
  fs.mkdirSync(sessionDir, { recursive: true });
}

// 确保会话目录有正确的权限
try {
  fs.accessSync(sessionDir, fs.constants.R_OK | fs.constants.W_OK);
  console.log('会话目录权限正确');
} catch (err) {
  console.error('会话目录权限错误:', err);
  console.log('尝试修复权限...');
  try {
    // 尝试设置权限，但这可能需要root权限
    fs.chmodSync(sessionDir, 0o700);
    console.log('权限修复成功');
  } catch (chmodErr) {
    console.error('无法修复权限:', chmodErr);
    console.log('请手动设置会话目录权限: chmod -R 700 ' + sessionDir);
  }
}

// 使用文件存储会话
const sessionSecret = config.sessionSecret;
if (!sessionSecret) {
  console.warn('警告: SESSION_SECRET 未配置，使用默认值可能存在安全风险');
}

app.use(session({
  store: new FileStore({
    path: sessionDir,
    ttl: config.sessionTtl,
    retries: 0,
    secret: sessionSecret || 'fallback-session-secret',
    logFn: function(message) {
      if (process.env.NODE_ENV === 'development') {
        console.log('[session-file-store]', message);
      }
    }
  }),
  secret: sessionSecret || 'fallback-session-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    maxAge: config.sessionTtl * 1000,
    httpOnly: true,
    sameSite: 'lax'
  }
}));

// 设置视图引擎
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// 登录路由
app.get('/login', (req, res) => {
  // 如果认证功能未启用或已经登录，重定向到首页
  if (!config.authEnabled || (req.session && req.session.isAuthenticated)) {
    return res.redirect('/');
  }

  res.render('login', {
    title: 'HTML-Go | 登录',
    error: null
  });
});

app.post('/login', authRateLimiter, (req, res) => {
  const { password } = req.body;

  if (!config.authEnabled) {
    return res.redirect('/');
  }

  if (!config.authPassword) {
    return res.status(500).render('login', {
      title: 'HTML-Go | 登录',
      error: '管理员密码未配置'
    });
  }

  if (!password) {
    return res.render('login', {
      title: 'HTML-Go | 登录',
      error: '请输入密码'
    });
  }

  if (password === config.authPassword) {
    req.session.isAuthenticated = true;

    res.cookie('auth', 'true', {
      maxAge: 24 * 60 * 60 * 1000,
      httpOnly: true,
      secure: req.secure || req.headers['x-forwarded-proto'] === 'https',
      sameSite: 'lax'
    });

    return res.redirect('/');
  }

  res.render('login', {
    title: 'HTML-Go | 登录',
    error: '密码错误，请重试'
  });
});

// 退出登录路由
app.get('/logout', (req, res) => {
  // 清除会话
  req.session.destroy();
  res.redirect('/login');
});

// API 路由设置
// 将 API 路由分为两部分：需要认证的和不需要认证的

// 导入路由处理函数
const { createPage, getPageById, getRecentPages, setPageProtection } = require('./models/pages');

// 创建页面的 API 需要认证
app.post('/api/pages/create', isAuthenticated, async (req, res) => {
  try {
    const schema = Joi.object({
      htmlContent: Joi.string().max(50000).required(),
      isProtected: Joi.boolean().default(false),
      codeType: Joi.string().valid('html', 'markdown', 'svg', 'mermaid').optional()
    });

    const { value, error } = schema.validate(req.body);

    if (error) {
      return res.status(400).json({ success: false, error: '请求参数不合法' });
    }

    const result = await createPage(value.htmlContent, value.isProtected, value.codeType);

    res.json({
      success: true,
      urlId: result.urlId,
      password: result.password,
      isProtected: result.isProtected
    });
  } catch (error) {
    console.error('创建页面API错误:', error);
    res.status(500).json({
      success: false,
      error: '服务器错误'
    });
  }
});

// 其他 API 不需要认证
app.use('/api/pages', pagesRoutes);

// 密码验证路由 - 用于AJAX验证
app.post('/validate-password/:id', passwordAttemptLimiter, async (req, res) => {
  try {
    const { id } = req.params;
    const schema = Joi.object({ password: Joi.string().length(5).pattern(/^[0-9]+$/).required() });
    const { value, error } = schema.validate(req.body);

    if (error) {
      return res.json({ valid: false });
    }

    const page = await getPageById(id);

    if (!page || page.is_protected !== 1 || !page.password) {
      return res.json({ valid: false });
    }

    const isValid = await bcrypt.compare(value.password, page.password);

    if (isValid) {
      req.session[`page_auth_${id}`] = true;
      return res.json({ valid: true });
    }

    return res.json({ valid: false });
  } catch (error) {
    console.error('密码验证错误:', error);
    return res.status(500).json({ valid: false, error: '服务器错误' });
  }
});

// 首页路由 - 需要登录才能访问
app.get('/', isAuthenticated, (req, res) => {
  res.render('index', { title: 'HTML-Go | 分享 HTML 代码的简单方式' });
});

// 导入代码类型检测和内容渲染工具
const { detectCodeType } = require('./utils/codeDetector');
const { renderContent } = require('./utils/contentRenderer');

// 查看页面路由 - 无需登录即可访问
app.get('/view/:id', async (req, res) => {
  try {
    const { getPageById } = require('./models/pages');
    const { id } = req.params;
    const page = await getPageById(id);

    if (!page) {
      return res.status(404).render('error', {
        title: '页面未找到',
        message: '您请求的页面不存在或已被删除'
      });
    }

    // 检查是否需要密码验证
    if (page.is_protected === 1) {
      if (!req.session[`page_auth_${id}`]) {
        return res.render('password', {
          title: 'HTML-Go | 密码保护',
          id: id,
          error: null
        });
      }
    }

    // 始终重新检测内容类型，确保正确渲染
    const validTypes = ['html', 'markdown', 'svg', 'mermaid'];

    // 打印原始内容的前100个字符，帮助调试
    console.log(`原始内容前100字符: ${page.html_content.substring(0, 100)}...`);

    // 导入代码块提取函数
    const { extractCodeBlocks } = require('./utils/codeDetector');

    // 尝试提取代码块
    const codeBlocks = extractCodeBlocks(page.html_content);

    // 如果找到代码块，处理它们
    let processedContent = page.html_content;
    let detectedType = 'html'; // 默认类型为HTML

    if (codeBlocks.length > 0) {
      console.log(`[DEBUG] 找到${codeBlocks.length}个代码块`);

      // 如果只有一个代码块，并且它几乎占据了整个内容，直接使用该代码块的内容和类型
      if (codeBlocks.length === 1 &&
          codeBlocks[0].content.length > page.html_content.length * 0.7) {
        processedContent = codeBlocks[0].content;
        detectedType = codeBlocks[0].type;
        console.log(`[DEBUG] 使用单个代码块内容，类型: ${detectedType}`);
      }
      // 如果有多个代码块，创建一个HTML文档来包含所有代码块
      else if (codeBlocks.length > 1) {
        // 创建一个HTML文档，包含所有代码块
        let htmlContent = '<!DOCTYPE html>\n<html>\n<head>\n<meta charset="UTF-8">\n';
        htmlContent += '<title>多代码块内容</title>\n';
        htmlContent += '<style>\n';
        htmlContent += '.code-block { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }\n';
        htmlContent += '.code-block-header { font-weight: bold; margin-bottom: 10px; }\n';
        htmlContent += '</style>\n';
        htmlContent += '</head>\n<body>\n';

        // 为每个代码块创建一个div
        codeBlocks.forEach((block, index) => {
          htmlContent += `<div class="code-block">\n`;
          htmlContent += `<div class="code-block-header">代码块 ${index + 1} (${block.originalType})</div>\n`;

          // 根据代码块类型渲染内容
          if (block.type === 'mermaid') {
            htmlContent += `<div class="mermaid">\n${block.content}\n</div>\n`;
          } else if (block.type === 'svg') {
            htmlContent += block.content;
          } else if (block.type === 'html') {
            htmlContent += block.content;
          } else {
            // 对于其他类型，使用pre标签
            htmlContent += `<pre>\n${block.content}\n</pre>\n`;
          }

          htmlContent += '</div>\n';
        });

        htmlContent += '</body>\n</html>';
        processedContent = htmlContent;
        detectedType = 'html';
        console.log('[DEBUG] 创建了包含多个代码块的HTML文档');
      }
    } else {
      // 没有找到代码块，使用原始的检测逻辑
      // 检查是否是 Mermaid 图表
      const mermaidPatterns = [
        /^\s*graph\s+[A-Za-z\s]/i,        // 流程图 (包括 graph TD)
        /^\s*flowchart\s+[A-Za-z\s]/i,    // 流程图 (新语法)
        /^\s*sequenceDiagram/i,           // 序列图
        /^\s*classDiagram/i,              // 类图
        /^\s*gantt/i,                    // 甘特图
        /^\s*pie/i,                      // 饼图
        /^\s*erDiagram/i,                // ER图
        /^\s*journey/i,                  // 用户旅程图
        /^\s*stateDiagram/i,             // 状态图
        /^\s*gitGraph/i                  // Git图
      ];

      // 检查是否是纯 Mermaid 语法
      const trimmedContent = page.html_content.trim();
      const isPureMermaid = mermaidPatterns.some(pattern => pattern.test(trimmedContent));

      // 使用detectCodeType函数检测内容类型
      detectedType = detectCodeType(page.html_content);

      // 安全检查: 如果内容以<!DOCTYPE html>或<html开头，强制识别为HTML
      if (page.html_content.trim().startsWith('<!DOCTYPE html>') ||
          page.html_content.trim().startsWith('<html')) {
        console.log('[DEBUG] 强制识别为完整HTML文档');
        detectedType = 'html';
      }
      // 如果是纯 Mermaid 语法，强制设置为 mermaid 类型
      else if (isPureMermaid) {
        console.log('[DEBUG] 检测到纯 Mermaid 语法，强制设置为 mermaid 类型');
        detectedType = 'mermaid';
      }
    }

    console.log(`检测到的内容类型: ${detectedType}`);
    console.log(`数据库中的内容类型: ${page.code_type}`);

    // 使用检测到的类型，确保正确渲染
    const contentType = validTypes.includes(detectedType) ? detectedType : 'html';

    // 根据不同的内容类型进行渲染
    const renderedContent = await renderContent(processedContent, contentType);

    // 在渲染内容中添加代码类型信息
    // 使用正则表达式在 head 标签结束前添加一个元数据标签
    const contentWithTypeInfo = renderedContent.replace(
      '</head>',
      `<meta name="code-type" content="${contentType}">
</head>`
    );

    // 返回渲染后的内容
    res.send(contentWithTypeInfo);
  } catch (error) {
    console.error('查看页面错误:', error);
    res.status(500).render('error', {
      title: '服务器错误',
      message: '查看页面时发生错误，请稍后再试'
    });
  }
});

// 注意：escapeHtml函数已经从 contentRenderer.js 导入，这里不需要重复定义

// 错误处理
app.use((req, res) => {
  res.status(404).render('error', {
    title: '页面未找到',
    message: '您请求的页面不存在'
  });
});

// 启动应用
initDatabase().then(() => {
  // 添加更多调试日志
  console.log('数据库初始化成功');
  console.log(`当前环境: ${process.env.NODE_ENV}`);
  console.log(`配置端口: ${config.port}`);
  console.log(`实际使用端口: ${PORT}`);
  console.log(`日志级别: ${config.logLevel}`);

  app.listen(PORT, () => {
    console.log(`服务器运行在 http://localhost:${PORT}`);

    // 添加路由处理器日志
    console.log('已注册的路由:');
    app._router.stack.forEach(middleware => {
      if(middleware.route) { // 路由
        console.log(`${Object.keys(middleware.route.methods)} ${middleware.route.path}`);
      }
    });
  });
}).catch(err => {
  console.error('数据库初始化失败:', err);
});

module.exports = app;

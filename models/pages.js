const { run, get, query } = require('./db');
const CryptoJS = require('crypto-js');
const bcrypt = require('bcrypt');

/**
 * 生成随机密码（5位纯数字）
 * @returns {string} 返回5位纯数字密码
 */
function generateRandomPassword() {
  const chars = '0123456789';
  let password = '';
  for (let i = 0; i < 5; i++) {
    const randomIndex = Math.floor(Math.random() * chars.length);
    password += chars[randomIndex];
  }
  return password;
}

/**
 * 创建新页面
 * @param {string} htmlContent HTML内容
 * @param {boolean} isProtected 是否启用密码保护
 * @param {string} codeType 代码类型（html, markdown, svg, mermaid）
 * @returns {Promise<Object>} 返回生成的URL ID和密码
 */
async function createPage(htmlContent, isProtected = false, codeType = 'html') {
  try {
    // 生成时间戳
    const timestamp = new Date().getTime().toString();
    
    // 生成短ID (7位)
    const hash = CryptoJS.MD5(htmlContent + timestamp).toString();
    const urlId = hash.substring(0, 7);
    
    const needsProtection = Boolean(isProtected);
    let plainPassword = null;
    let storedPassword = null;

    if (needsProtection) {
      plainPassword = generateRandomPassword();
      storedPassword = await bcrypt.hash(plainPassword, 10);
    }
    
    // 保存到数据库
    // isProtected决定是否需要密码才能访问
    await run(
      'INSERT INTO pages (id, html_content, created_at, password, is_protected, code_type) VALUES (?, ?, ?, ?, ?, ?)',
      [urlId, htmlContent, Date.now(), storedPassword, needsProtection ? 1 : 0, codeType]
    );
    
    return { urlId, password: plainPassword, isProtected: needsProtection };
  } catch (error) {
    console.error('创建页面错误:', error);
    throw error;
  }
}

/**
 * 通过ID获取页面
 * @param {string} id 页面ID
 * @returns {Promise<Object|null>} 返回页面对象或null
 */
async function getPageById(id) {
  try {
    return await get('SELECT * FROM pages WHERE id = ?', [id]);
  } catch (error) {
    console.error('获取页面错误:', error);
    throw error;
  }
}

/**
 * 获取最近创建的页面列表
 * @param {number} limit 限制数量
 * @returns {Promise<Array>} 返回页面列表
 */
async function getRecentPages(limit = 10) {
  try {
    return await query(
      'SELECT id, created_at FROM pages ORDER BY created_at DESC LIMIT ?',
      [limit]
    );
  } catch (error) {
    console.error('获取最近页面错误:', error);
    throw error;
  }
}

/**
 * 更新页面保护状态
 * @param {string} id 页面ID
 * @param {boolean} enable 是否启用保护
 * @returns {Promise<{password: string|null, isProtected: boolean}>}
 */
async function setPageProtection(id, enable) {
  const page = await getPageById(id);
  if (!page) {
    return null;
  }

  if (enable) {
    const password = generateRandomPassword();
    const hashedPassword = await bcrypt.hash(password, 10);
    await run(
      'UPDATE pages SET is_protected = 1, password = ? WHERE id = ?',
      [hashedPassword, id]
    );
    return { password, isProtected: true };
  }

  await run(
    'UPDATE pages SET is_protected = 0, password = NULL WHERE id = ?',
    [id]
  );

  return { password: null, isProtected: false };
}

module.exports = {
  createPage,
  getPageById,
  getRecentPages,
  setPageProtection
};

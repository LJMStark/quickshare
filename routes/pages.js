const express = require('express');
const router = express.Router();
const Joi = require('joi');
const { isAuthenticated } = require('../middleware/auth');
const { getPageById, getRecentPages, setPageProtection } = require('../models/pages');

// 创建页面的路由已移至 app.js，并添加了认证中间件

/**
 * 获取页面信息
 * GET /api/pages/:id
 */
router.get('/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const page = await getPageById(id);

    if (!page) {
      return res.status(404).json({
        success: false,
        error: '页面不存在'
      });
    }

    res.json({
      success: true,
      page: {
        id: page.id,
        createdAt: page.created_at
      }
    });
  } catch (error) {
    console.error('获取页面API错误:', error);
    res.status(500).json({
      success: false,
      error: '服务器错误',
      details: error.message
    });
  }
});

/**
 * 获取最近页面列表
 * GET /api/pages/list/recent
 */
router.get('/list/recent', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 10;
    const pages = await getRecentPages(limit);

    res.json({
      success: true,
      pages
    });
  } catch (error) {
    console.error('获取最近页面API错误:', error);
    res.status(500).json({
      success: false,
      error: '服务器错误',
      details: error.message
    });
  }
});

/**
 * 更新页面的保护状态
 * POST /api/pages/:id/protect
 */
const protectSchema = Joi.object({
  isProtected: Joi.boolean().required()
});

router.post('/:id/protect', isAuthenticated, async (req, res) => {
  try {
    const { id } = req.params;
    const { value, error } = protectSchema.validate(req.body);

    if (error) {
      return res.status(400).json({ success: false, error: '无效的参数' });
    }

    const result = await setPageProtection(id, value.isProtected);

    if (!result) {
      return res.status(404).json({ success: false, error: '页面不存在' });
    }

    res.json({ success: true, password: result.password, isProtected: result.isProtected });
  } catch (err) {
    console.error('更新保护状态API错误:', err);
    res.status(500).json({ success: false, error: '更新保护状态失败' });
  }
});

module.exports = router;

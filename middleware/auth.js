/**
 * 认证中间件
 * 用于保护需要登录才能访问的路由
 */

/**
 * 检查用户是否已认证
 * 如果未认证，重定向到登录页面
 */
function isAuthenticated(req, res, next) {
  const authEnabled = req.app.locals.config.authEnabled;

  if (!authEnabled) {
    return next();
  }

  if (req.session?.isAuthenticated) {
    return next();
  }

  res.redirect('/login');
}

module.exports = {
  isAuthenticated
};

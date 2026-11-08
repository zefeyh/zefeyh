<?php
/**
 * 网址导航后台 admin.php
 * ------------------------------------------------------------------
 * 功能：网址 / 栏目 增删改查、图标上传与安全抓取、静态导航页自动生成、
 *       系统设置、密码管理、数据快照备份与恢复。
 *
 * 安全：密码 PBKDF2-SHA256 加盐存储、会话空闲超时 + UA 绑定、CSRF 令牌、
 *       登录暴力破解限流、所有输出转义、URL/图标路径白名单、上传内容嗅探、
 *       SVG 净化、图标抓取 SSRF 防护、文件原子写入、严格 CSP（脚本/样式哈希）、
 *       敏感目录禁止 Web 访问。
 *
 * 数据存储：admin/data/nav.sqlite（网址、栏目、设置、登录限流全部存于 SQLite）。
 * 目录结构：public/（静态页 + css/ico/fonts）、admin/（后台程序、模板、数据库、备份）。
 * 兼容 PHP 7.0+（需启用 pdo_sqlite 扩展）；PHP 5.6 亦可运行。
 */

error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');
ini_set('html_errors', '0');

define('NAV_ROOT', __DIR__);                            /* admin/  后台与数据目录 */
define('PUBLIC_ROOT', dirname(__DIR__) . '/public');   /* public/ 站点静态资源与首页 */
define('DB_DIR', NAV_ROOT . '/data');
define('DB_FILE', DB_DIR . '/nav.sqlite');
define('TEMPLATE_FILE', NAV_ROOT . '/template.html');
define('UPLOAD_DIR', PUBLIC_ROOT . '/ico/');
define('BACKUP_DIR', NAV_ROOT . '/backup/');
define('ADMIN_CSS_FILE', PUBLIC_ROOT . '/css/admin.css');
define('PBKDF2_ITERATIONS', 210000);
define('MAX_UPLOAD_SIZE', 512 * 1024);
define('MAX_ICON_SIZE', 512 * 1024);
define('PER_PAGE', 40);
define('LOGIN_MAX_FAILS', 5);
define('LOGIN_LOCK_SECONDS', 900);

/* 图片扩展名白名单（不含任何脚本类文件） */
$NAV_IMAGE_EXT = array('png', 'jpg', 'jpeg', 'gif', 'ico', 'webp', 'svg');

/* 标签白名单：键 => 中文说明（与静态页 iconMap 一一对应） */
$NAV_REMARKS = array(
    'windows' => '微软系统适用',
    'mac'     => '苹果系统适用',
    'linux'   => 'linux系统适用',
    'android' => '安卓系统适用',
    'fufei'   => '需要付费使用',
    'kexue'   => '大陆地区无法访问',
    'heart'   => '推荐网站',
    'github'  => 'github资源'
);

if (!function_exists('hash_equals')) {
    function hash_equals($known, $user) {
        if (!is_string($known) || !is_string($user) || strlen($known) !== strlen($user)) return false;
        $diff = 0;
        for ($i = 0, $n = strlen($known); $i < $n; $i++) $diff |= ord($known[$i]) ^ ord($user[$i]);
        return $diff === 0;
    }
}

/* ==================================================================
 * 一、通用工具
 * ================================================================== */

function h($v) {
    return htmlspecialchars((string)$v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function post($k, $default = '') {
    return (isset($_POST[$k]) && is_string($_POST[$k])) ? $_POST[$k] : $default;
}

function getq($k, $default = '') {
    return (isset($_GET[$k]) && is_string($_GET[$k])) ? $_GET[$k] : $default;
}

function is_post() {
    return isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] === 'POST';
}

function is_https() {
    if (!empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off') return true;
    if (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && strtolower($_SERVER['HTTP_X_FORWARDED_PROTO']) === 'https') return true;
    return isset($_SERVER['SERVER_PORT']) && (int)$_SERVER['SERVER_PORT'] === 443;
}

function is_ajax() {
    return post('ajax') === '1' ||
        (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && $_SERVER['HTTP_X_REQUESTED_WITH'] === 'fetch');
}

function random_bytes_safe($n) {
    if (function_exists('random_bytes')) {
        try { return random_bytes($n); } catch (Exception $e) { /* 继续降级 */ }
    }
    if (function_exists('openssl_random_pseudo_bytes')) {
        $strong = false;
        $b = @openssl_random_pseudo_bytes($n, $strong);
        if ($b !== false && $strong) return $b;
    }
    $b = '';
    for ($i = 0; $i < $n; $i++) $b .= chr(mt_rand(0, 255));
    return $b;
}

function random_hex($bytes) {
    return bin2hex(random_bytes_safe($bytes));
}

function nav_url($params = array()) {
    $base = isset($_SERVER['SCRIPT_NAME']) ? basename($_SERVER['SCRIPT_NAME']) : 'admin.php';
    if (!preg_match('/^[A-Za-z0-9_\-]+\.php$/', $base)) $base = 'admin.php';
    $q = http_build_query($params);
    return $base . ($q !== '' ? '?' . $q : '');
}

/* ==================================================================
 * 后台页面资源地址
 *
 * 数据库与静态页里的图标值是相对 public/ 的路径（./ico/xxx.png）。
 * 后台入口可能位于 /admin.php、/public/admin.php、/admin/admin.php
 * 等不同 URL，浏览器按「当前脚本所在目录」解析 ./ico/... 就会 404。
 * 这里由 SCRIPT_NAME 推算出 public/ 的绝对 Web 路径，后台的图片、
 * 样式、静态页链接都用它拼装，与入口所在目录无关。
 *
 * 只影响后台页面的显示：数据库原值、public/ico/ 下的文件、
 * 以及生成的 public/index.html 均不作任何改动。
 * ================================================================== */
function public_base_url() {
    static $base = null;
    if ($base !== null) return $base;
    $script = isset($_SERVER['SCRIPT_NAME']) ? (string)$_SERVER['SCRIPT_NAME'] : '/admin.php';
    $script = str_replace('\\', '/', $script);
    if ($script === '' || $script[0] !== '/') $script = '/' . ltrim($script, '/');
    /* PATH_INFO 不属于脚本路径 */
    $cut = strpos($script, '.php/');
    if ($cut !== false) $script = substr($script, 0, $cut + 4);
    $dir = rtrim(str_replace('\\', '/', dirname($script)), '/');
    /* 若直接访问 admin/admin.php，public/ 是它的兄弟目录 */
    if (strtolower(basename($dir)) === 'admin') {
        $parent = rtrim(str_replace('\\', '/', dirname($dir)), '/');
        $dir = ($parent === '' || $parent === '/') ? '/public' : $parent . '/public';
    }
    $base = ($dir === '' || $dir === '/') ? '/' : rtrim($dir, '/') . '/';
    if (!preg_match('#^/[A-Za-z0-9_\-./]*$#', $base) || strpos($base, '..') !== false) $base = '/';
    return $base;
}

function public_asset_url($rel) {
    $rel = ltrim(preg_replace('#^\./#', '', trim(str_replace('\\', '/', (string)$rel))), '/');
    if ($rel === '' || strpos($rel, '..') !== false || !preg_match('#^[A-Za-z0-9_\-./]+$#', $rel)) {
        $rel = 'ico/default.png';
    }
    return public_base_url() . $rel;
}

/** 依文件魔数返回真实 MIME；不是图片（例如抓取失败保存的 HTML）返回 null */
function icon_real_mime($path) {
    $fh = @fopen($path, 'rb');
    if (!$fh) return null;
    $b = (string)@fread($fh, 512);
    fclose($fh);
    if (substr($b, 0, 8) === "\x89PNG\r\n\x1a\n") return 'image/png';
    if (substr($b, 0, 3) === "\xff\xd8\xff") return 'image/jpeg';
    if (substr($b, 0, 3) === 'GIF') return 'image/gif';
    if (substr($b, 0, 4) === 'RIFF' && substr($b, 8, 4) === 'WEBP') return 'image/webp';
    if (substr($b, 0, 4) === "\x00\x00\x01\x00" || substr($b, 0, 4) === "\x00\x00\x02\x00") return 'image/x-icon';
    if (preg_match('/<svg\b/i', $b)) return 'image/svg+xml';
    return null;
}

/** 后台兜底图标：直接内嵌为 data URI，任何部署路径下都不会 404 */
function default_icon_uri() {
    static $uri = null;
    if ($uri !== null) return $uri;
    $p = PUBLIC_ROOT . '/ico/default.png';
    $data = is_file($p) ? @file_get_contents($p) : false;
    if ($data !== false && icon_real_mime($p) === 'image/png' && strlen($data) <= 65536) {
        $uri = 'data:image/png;base64,' . base64_encode($data);
    } else {
        /* 连默认图都缺失时，用一张极小的内置占位图 */
        $uri = 'data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22 width=%2232%22 height=%2232%22%3E%3Crect width=%2232%22 height=%2232%22 rx=%226%22 fill=%22%23eef1f7%22/%3E%3C/svg%3E';
    }
    return $uri;
}

/**
 * 把数据库里的图标值转换成后台可正常显示的 URL：
 * 1) 本地图标拼上 public/ 的绝对 Web 路径，不再依赖入口所在目录；
 * 2) 文件缺失或内容不是图片时直接回退默认图标，避免破图与 404；
 * 3) 扩展名与真实格式不符时（历史抓取的 favicon 常见）用 data URI
 *    指定正确 MIME，避免服务器按扩展名发送错误类型导致浏览器拒绝解码。
 * 数据库原值与静态页输出保持不变。
 */
function admin_icon_url($logo) {
    $v = str_replace('\\', '/', trim((string)$logo));
    $default = default_icon_uri();
    if ($v !== '' && preg_match('#^https?://#i', $v)) {
        $u = clean_url($v);
        return $u === '' ? $default : $u;
    }
    $rel = ltrim(preg_replace('#^\./#', '', $v), '/');
    if ($rel === '' || strpos($rel, '..') !== false || !preg_match('#^ico/[A-Za-z0-9_\-./]+$#', $rel)) {
        return $default;
    }
    $full = PUBLIC_ROOT . '/' . $rel;
    if (!is_file($full)) return $default;
    $mime = icon_real_mime($full);
    if ($mime === null) return $default;
    $ext = strtolower(pathinfo($rel, PATHINFO_EXTENSION));
    $expect = array(
        'png' => 'image/png', 'jpg' => 'image/jpeg', 'jpeg' => 'image/jpeg',
        'gif' => 'image/gif', 'webp' => 'image/webp',
        'ico' => 'image/x-icon', 'svg' => 'image/svg+xml'
    );
    if (!isset($expect[$ext]) || $expect[$ext] !== $mime) {
        $data = @file_get_contents($full);
        /* 只内嵌小图，避免列表页体积膨胀；大图仍走 URL，浏览器按文件魔数解码 */
        if ($data !== false && strlen($data) <= 24576) {
            return 'data:' . $mime . ';base64,' . base64_encode($data);
        }
    }
    return public_asset_url($rel);
}

function redirect($params = array()) {
    header('Location: ' . nav_url($params), true, 303);
    exit;
}

function flash($type, $msg) {
    $_SESSION['flash'] = array('type' => $type, 'msg' => $msg);
}

function take_flash() {
    $f = isset($_SESSION['flash']) ? $_SESSION['flash'] : null;
    unset($_SESSION['flash']);
    return $f;
}

function clean_text($v, $max) {
    $v = (string)$v;
    $v = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $v);
    $v = trim($v);
    if ($max > 0) {
        if (function_exists('mb_substr')) $v = mb_substr($v, 0, $max, 'UTF-8');
        else if (strlen($v) > $max * 4) $v = substr($v, 0, $max * 4);
    }
    return $v;
}

function json_flags($extra) {
    $flags = JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | $extra;
    if (defined('JSON_INVALID_UTF8_SUBSTITUTE')) $flags |= constant('JSON_INVALID_UTF8_SUBSTITUTE');
    return $flags;
}

/* ==================================================================
 * SQLite 数据层：网址 / 栏目 / 设置 / 登录限流全部存于单库
 * ================================================================== */

$GLOBALS['NAV_PDO'] = null;

function db() {
    if ($GLOBALS['NAV_PDO'] instanceof PDO) return $GLOBALS['NAV_PDO'];
    if (!extension_loaded('pdo_sqlite')) {
        die('服务器未启用 pdo_sqlite 扩展，请在 php.ini 中启用 extension=pdo_sqlite 后重试。');
    }
    if (!is_dir(DB_DIR)) @mkdir(DB_DIR, 0755, true);
    try {
        $pdo = new PDO('sqlite:' . DB_FILE, null, null, array(
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
        ));
        $pdo->exec('PRAGMA busy_timeout = 5000');
        $pdo->exec('PRAGMA foreign_keys = ON');
        $GLOBALS['NAV_PDO'] = $pdo;
        return $pdo;
    } catch (Exception $e) {
        die('SQLite 数据库无法打开：' . h($e->getMessage()));
    }
}

function db_close() {
    $GLOBALS['NAV_PDO'] = null;
}

function db_init() {
    $p = db();
    $sql = array(
        "CREATE TABLE IF NOT EXISTS websites (id INTEGER PRIMARY KEY AUTOINCREMENT, sid TEXT NOT NULL UNIQUE, category TEXT NOT NULL DEFAULT '', name TEXT NOT NULL DEFAULT '', url TEXT NOT NULL DEFAULT '', logo TEXT NOT NULL DEFAULT '', descr TEXT NOT NULL DEFAULT '', tags TEXT NOT NULL DEFAULT '', sort INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL DEFAULT '')",
        "CREATE INDEX IF NOT EXISTS idx_websites_sort ON websites(sort, id)",
        "CREATE INDEX IF NOT EXISTS idx_websites_cat ON websites(category)",
        "CREATE TABLE IF NOT EXISTS categories (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, sort INTEGER NOT NULL DEFAULT 0)",
        "CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS throttle (k TEXT PRIMARY KEY, fails INTEGER NOT NULL DEFAULT 0, first_at INTEGER NOT NULL DEFAULT 0, locked_until INTEGER NOT NULL DEFAULT 0)"
    );
    foreach ($sql as $q) $p->exec($q);
    return $p;
}

function setting_get($key, $default = '') {
    $st = db()->prepare('SELECT value FROM settings WHERE key = ?');
    $st->execute(array($key));
    $v = $st->fetchColumn();
    return $v === false ? $default : (string)$v;
}

function setting_set($key, $value) {
    $st = db()->prepare('INSERT OR REPLACE INTO settings(key, value) VALUES(?, ?)');
    return $st->execute(array($key, (string)$value));
}

/** 一次事务内整体替换网址与栏目，避免半写状态 */
function db_save_all($rows, $cats) {
    $p = db();
    try {
        $p->beginTransaction();
        $p->exec('DELETE FROM websites');
        $ins = $p->prepare('INSERT INTO websites(sid, category, name, url, logo, descr, tags, sort, updated_at) VALUES(?,?,?,?,?,?,?,?,?)');
        $seen = array();
        $now = date('c');
        $i = 0;
        foreach ($rows as $r) {
            $sid = isset($r['id']) ? (string)$r['id'] : '';
            if ($sid === '' || isset($seen[$sid])) {
                do { $sid = 'w_' . substr(random_hex(6), 0, 12); } while (isset($seen[$sid]));
            }
            $seen[$sid] = 1;
            $tags = (isset($r['remark']) && is_array($r['remark'])) ? implode(',', $r['remark']) : '';
            $ins->execute(array(
                $sid,
                isset($r['category']) ? $r['category'] : '',
                isset($r['name']) ? $r['name'] : '',
                isset($r['url']) ? $r['url'] : '',
                isset($r['logo']) ? $r['logo'] : '',
                isset($r['desc']) ? $r['desc'] : '',
                $tags, $i++, $now
            ));
        }
        $p->exec('DELETE FROM categories');
        $ins2 = $p->prepare('INSERT INTO categories(name, sort) VALUES(?, ?)');
        $seenCat = array();
        $j = 0;
        foreach ($cats as $c) {
            $c = (string)$c;
            if ($c === '' || isset($seenCat[$c])) continue;
            $seenCat[$c] = 1;
            $ins2->execute(array($c, $j++));
        }
        setting_set('data_updated', $now);
        return $p->commit();
    } catch (Exception $e) {
        if ($p->inTransaction()) $p->rollBack();
        return false;
    }
}

/** 复制一份一致的数据库文件（快照 / 导出 / 恢复前备份） */
function db_copy_to($path) {
    $dir = dirname($path);
    if (!is_dir($dir)) @mkdir($dir, 0755, true);
    try { @db()->exec('PRAGMA wal_checkpoint(TRUNCATE)'); } catch (Exception $e) { /* 非 WAL 模式可忽略 */ }
    if (!@copy(DB_FILE, $path)) return false;
    @chmod($path, 0600);
    return true;
}

/** 用快照覆盖当前库：先校验文件头，再关闭连接后原子替换 */
function db_restore_from($path) {
    if (!is_file($path)) return false;
    $fh = @fopen($path, 'rb');
    if (!$fh) return false;
    $head = fread($fh, 16);
    fclose($fh);
    if (strpos($head, 'SQLite format 3') !== 0) return false;
    if (!is_dir(DB_DIR)) @mkdir(DB_DIR, 0755, true);
    db_close();
    $tmp = DB_DIR . '/restore-' . random_hex(4) . '.tmp';
    if (!@copy($path, $tmp)) return false;
    if (!@rename($tmp, DB_FILE)) {
        if (!@copy($tmp, DB_FILE)) { @unlink($tmp); return false; }
        @unlink($tmp);
    }
    @chmod(DB_FILE, 0600);
    return true;
}

/** 同目录临时文件 + 原子替换，避免写一半导致数据损坏 */
function atomic_write($path, $content) {
    $dir = dirname($path);
    if (!is_dir($dir)) @mkdir($dir, 0755, true);
    $tmp = @tempnam($dir, '.nvt');
    if ($tmp === false) return false;
    if (@file_put_contents($tmp, $content, LOCK_EX) === false) { @unlink($tmp); return false; }
    @chmod($tmp, 0644);
    if (@rename($tmp, $path)) return true;
    /* Windows 下 rename 目标已存在会失败，退化为覆盖写 */
    if (DIRECTORY_SEPARATOR === '\\' && is_file($path) && @copy($tmp, $path)) {
        @unlink($tmp);
        return true;
    }
    @unlink($tmp);
    return false;
}

function ensure_dirs() {
    if (!is_dir(UPLOAD_DIR)) @mkdir(UPLOAD_DIR, 0755, true);
    if (!is_dir(BACKUP_DIR)) @mkdir(BACKUP_DIR, 0755, true);
    if (!is_dir(DB_DIR)) @mkdir(DB_DIR, 0755, true);
    $deny = "# 禁止通过 Web 直接访问\n<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n    Order allow,deny\n    Deny from all\n</IfModule>\nOptions -Indexes\n";
    if (!is_file(BACKUP_DIR . '.htaccess')) @file_put_contents(BACKUP_DIR . '.htaccess', $deny);
    if (!is_file(DB_DIR . '/.htaccess')) @file_put_contents(DB_DIR . '/.htaccess', $deny);
    if (!is_file(UPLOAD_DIR . '.htaccess')) {
        $ico = "# 图标目录：只允许静态图片，禁止脚本解析\n"
             . "<FilesMatch \"\\.(php|phtml|phar|php[0-9]|pht|shtml|cgi|pl|py|asp|aspx|jsp|sh|html?)$\">\n"
             . "    <IfModule mod_authz_core.c>\n        Require all denied\n    </IfModule>\n"
             . "    <IfModule !mod_authz_core.c>\n        Order allow,deny\n        Deny from all\n    </IfModule>\n</FilesMatch>\n"
             . "<FilesMatch \"\\.svg$\">\n    <IfModule mod_headers.c>\n"
             . "        Header set Content-Security-Policy \"default-src 'none'; style-src 'unsafe-inline'; img-src data:; sandbox\"\n"
             . "        Header set X-Content-Type-Options \"nosniff\"\n    </IfModule>\n</FilesMatch>\n"
             . "Options -Indexes\n";
        @file_put_contents(UPLOAD_DIR . '.htaccess', $ico);
    }
}

function rotate_files($pattern, $keep) {
    $files = glob(BACKUP_DIR . $pattern);
    if (!is_array($files) || count($files) <= $keep) return;
    usort($files, 'compare_mtime_desc');
    foreach (array_slice($files, $keep) as $f) @unlink($f);
}

function compare_mtime_desc($a, $b) {
    return @filemtime($b) - @filemtime($a);
}

function backup_existing($path, $prefix) {
    if (!is_file($path)) return '';
    ensure_dirs();
    $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
    /* 配置备份改为 .txt，避免极端情况下被当作 PHP 执行 */
    if ($ext === 'php') $ext = 'txt';
    $name = $prefix . '-' . date('Ymd-His') . '-' . substr(random_hex(3), 0, 6) . '.' . $ext;
    if (@copy($path, BACKUP_DIR . $name)) {
        rotate_files($prefix . '-*.' . $ext, 20);
        return $name;
    }
    return '';
}

/* ==================================================================
 * 二、配置与密码
 * ================================================================== */

function config_defaults() {
    return array(
        'password_hash'   => '',
        'auto_generate'   => true,
        'output_file'     => 'index.html',
        'session_idle'    => 1800,
        'site_title'      => '梁老师网址导航',
        'default_password'=> false
    );
}

function output_filename($cfg) {
    $f = isset($cfg['output_file']) ? basename((string)$cfg['output_file']) : 'index.html';
    if (!preg_match('/^[A-Za-z0-9_\-]+\.html$/', $f)) $f = 'index.html';
    return $f;
}

function config_load() {
    db_init();
    $hash = setting_get('password_hash', '');
    if ($hash === '') return null;                 /* 未安装：进入首次初始化流程 */
    $c = config_defaults();
    $c['password_hash'] = $hash;
    $c['site_title'] = clean_text(setting_get('site_title', $c['site_title']), 60);
    if ($c['site_title'] === '') $c['site_title'] = '网址导航';
    $c['session_idle'] = max(300, min(86400, (int)setting_get('session_idle', 1800)));
    $c['auto_generate'] = setting_get('auto_generate', '1') === '1';
    $c['default_password'] = setting_get('default_password', '0') === '1';
    $c['output_file'] = output_filename($c);
    return $c;
}

/** 设置写入 settings 表；密码哈希同为 PBKDF2-SHA256 派生值，不含明文 */
function config_save($cfg) {
    $pairs = array(
        'password_hash'    => isset($cfg['password_hash']) ? $cfg['password_hash'] : '',
        'site_title'       => $cfg['site_title'],
        'output_file'      => output_filename($cfg),
        'session_idle'     => (int)$cfg['session_idle'],
        'auto_generate'    => !empty($cfg['auto_generate']) ? '1' : '0',
        'default_password' => !empty($cfg['default_password']) ? '1' : '0'
    );
    $p = db();
    try {
        $p->beginTransaction();
        foreach ($pairs as $k => $v) setting_set($k, $v);
        return $p->commit();
    } catch (Exception $e) {
        if ($p->inTransaction()) $p->rollBack();
        return false;
    }
}

/* 格式：pbkdf2_sha256$迭代次数$salt(hex)$hash(hex) —— 与既有配置兼容
 * 注意：hash_pbkdf2 的 length 参数在不开启 raw_output 时表示「十六进制字符数」，
 * 这里统一用 raw_output=true + bin2hex，确保得到 32 字节密钥的 64 位十六进制串。 */
function pbkdf2_hex($pw, $salt, $iter) {
    return bin2hex(hash_pbkdf2('sha256', (string)$pw, $salt, $iter, 32, true));
}

function password_hash_new($pw) {
    $salt = random_bytes_safe(16);
    return 'pbkdf2_sha256$' . PBKDF2_ITERATIONS . '$' . bin2hex($salt) . '$'
         . pbkdf2_hex($pw, $salt, PBKDF2_ITERATIONS);
}

function password_check($pw, $stored) {
    $p = explode('$', (string)$stored);
    if (count($p) !== 4 || $p[0] !== 'pbkdf2_sha256') return false;
    $iter = (int)$p[1];
    if ($iter < 10000 || $iter > 1000000) return false;
    $salt = @hex2bin($p[2]);
    if ($salt === false || strlen($p[3]) !== 64) return false;
    return hash_equals($p[3], pbkdf2_hex($pw, $salt, $iter));
}

/* ==================================================================
 * 三、会话、CSRF 与登录限流
 * ================================================================== */

function start_session($idle) {
    ini_set('session.use_only_cookies', '1');
    ini_set('session.use_strict_mode', '1');
    ini_set('session.cookie_httponly', '1');
    ini_set('session.cookie_secure', is_https() ? '1' : '0');
    ini_set('session.cookie_samesite', 'Lax');
    ini_set('session.gc_maxlifetime', (string)max($idle, 1800));
    session_name('NAVADMINSID');
    @session_start();
}

function csrf_token() {
    if (empty($_SESSION['csrf']) || !is_string($_SESSION['csrf'])) {
        $_SESSION['csrf'] = random_hex(32);
    }
    return $_SESSION['csrf'];
}

function csrf_field() {
    return '<input type="hidden" name="csrf_token" value="' . h(csrf_token()) . '">';
}

function csrf_valid() {
    $t = post('csrf_token');
    if ($t === '' && isset($_SERVER['HTTP_X_CSRF_TOKEN']) && is_string($_SERVER['HTTP_X_CSRF_TOKEN'])) {
        $t = $_SERVER['HTTP_X_CSRF_TOKEN'];
    }
    return $t !== '' && !empty($_SESSION['csrf']) && hash_equals($_SESSION['csrf'], $t);
}

function ua_hash() {
    return hash('sha256', isset($_SERVER['HTTP_USER_AGENT']) ? (string)$_SERVER['HTTP_USER_AGENT'] : '');
}

function clear_login($msg) {
    unset($_SESSION['logged_in'], $_SESSION['login_time'], $_SESSION['last_activity'],
          $_SESSION['ua_hash'], $_SESSION['csrf'], $_SESSION['last_icon']);
    if (session_status() === PHP_SESSION_ACTIVE) @session_regenerate_id(true);
    flash('error', $msg);
}

function is_logged_in($idle) {
    if (empty($_SESSION['logged_in'])) return false;
    $now = time();
    if (!isset($_SESSION['ua_hash']) || !hash_equals($_SESSION['ua_hash'], ua_hash())) {
        clear_login('浏览器环境发生变化，请重新登录');
        return false;
    }
    if (!isset($_SESSION['login_time']) || $now - (int)$_SESSION['login_time'] > 28800) {
        clear_login('登录已超过 8 小时，请重新登录');
        return false;
    }
    if (!isset($_SESSION['last_activity']) || $now - (int)$_SESSION['last_activity'] > $idle) {
        clear_login('会话已超时，请重新登录');
        return false;
    }
    $_SESSION['last_activity'] = $now;
    return true;
}

function client_ip() {
    return isset($_SERVER['REMOTE_ADDR']) ? (string)$_SERVER['REMOTE_ADDR'] : '0.0.0.0';
}

function throttle_key() {
    return hash('sha256', client_ip());
}

function throttle_locked_seconds() {
    $st = db()->prepare('SELECT locked_until FROM throttle WHERE k = ?');
    $st->execute(array(throttle_key()));
    $until = (int)$st->fetchColumn();
    return $until > time() ? $until - time() : 0;
}

function throttle_fail() {
    $p = db();
    $k = throttle_key();
    $now = time();
    $st = $p->prepare('SELECT fails, first_at, locked_until FROM throttle WHERE k = ?');
    $st->execute(array($k));
    $r = $st->fetch(PDO::FETCH_ASSOC);
    $fails = $r ? (int)$r['fails'] : 0;
    $first = $r ? (int)$r['first_at'] : $now;
    $until = $r ? (int)$r['locked_until'] : 0;
    if ($now - $first > LOGIN_LOCK_SECONDS) { $fails = 0; $first = $now; $until = 0; }
    $fails++;
    if ($fails >= LOGIN_MAX_FAILS) { $until = $now + LOGIN_LOCK_SECONDS; $fails = 0; }
    $w = $p->prepare('INSERT OR REPLACE INTO throttle(k, fails, first_at, locked_until) VALUES(?,?,?,?)');
    $w->execute(array($k, $fails, $first, $until));
    $del = $p->prepare('DELETE FROM throttle WHERE first_at < ? AND locked_until < ?');
    $del->execute(array($now - 3600, $now - 3600));
}

function throttle_reset() {
    $st = db()->prepare('DELETE FROM throttle WHERE k = ?');
    $st->execute(array(throttle_key()));
}

/* ==================================================================
 * 四、数据读写与规范化
 * ================================================================== */

function remark_options() {
    global $NAV_REMARKS;
    return $NAV_REMARKS;
}

function clean_category($v) {
    $v = clean_text($v, 30);
    if ($v === '') return '';
    if ($v === '全部' || $v === '__new__' || $v === '__uncategorized__') return '';
    foreach (array('<', '>', '"', "'", '\\', '/') as $ch) {
        if (strpos($v, $ch) !== false) return '';
    }
    return $v;
}

function clean_url($v) {
    $v = trim((string)$v);
    if ($v === '') return '';
    if (!preg_match('#^https?://#i', $v)) $v = 'https://' . $v;
    $v = preg_replace('/[\x00-\x20\x7F]/', '', $v);
    if (!filter_var($v, FILTER_VALIDATE_URL)) return '';
    $p = @parse_url($v);
    if (!is_array($p) || empty($p['scheme']) || empty($p['host'])) return '';
    $scheme = strtolower($p['scheme']);
    if ($scheme !== 'http' && $scheme !== 'https') return '';
    if (isset($p['user']) || isset($p['pass'])) return '';
    if (!preg_match('/^[A-Za-z0-9\.\-\[\]:]+$/', $p['host'])) return '';
    return $v;
}

function clean_logo($v) {
    $v = str_replace('\\', '/', trim((string)$v));
    if ($v === '') return './ico/default.png';
    if (preg_match('#^https?://#i', $v)) {
        $u = clean_url($v);
        return $u === '' ? '' : $u;
    }
    if (strpos($v, '..') !== false || strpos($v, '//') !== false) return '';
    if (!preg_match('#^(?:\./)?ico/[A-Za-z0-9_\-./]+$#', $v)) return '';
    $bn = basename($v);
    if ($bn === '' || $bn[0] === '.') return '';
    if (!preg_match('#\.(png|jpe?g|gif|ico|svg|webp)$#i', $bn)) return '';
    return './' . ltrim(preg_replace('#^\./#', '', $v), '/');
}

function clean_remark($v) {
    $out = array();
    if (!is_array($v)) return $out;
    $allowed = remark_options();
    foreach ($v as $r) {
        if (!is_string($r)) continue;
        $r = strtolower(trim($r));
        if (isset($allowed[$r]) && !in_array($r, $out, true)) $out[] = $r;
        if (count($out) >= 20) break;
    }
    return $out;
}

function new_site_id($rows) {
    do {
        $id = 'w_' . substr(random_hex(6), 0, 12);
        $dup = false;
        foreach ($rows as $r) if (isset($r['id']) && $r['id'] === $id) { $dup = true; break; }
    } while ($dup);
    return $id;
}

function normalize_site($r) {
    if (!is_array($r)) return null;
    $id = (isset($r['id']) && is_string($r['id']) && preg_match('/^[A-Za-z0-9_\-]{3,40}$/', $r['id']))
        ? $r['id'] : '';
    $logo = clean_logo(isset($r['logo']) ? $r['logo'] : '');
    return array(
        'id'       => $id,
        'category' => clean_text(isset($r['category']) ? $r['category'] : '', 60) ?: '未分类',
        'name'     => clean_text(isset($r['name']) ? $r['name'] : '', 100),
        'url'      => clean_url(isset($r['url']) ? $r['url'] : ''),
        'logo'     => $logo === '' ? './ico/default.png' : $logo,
        'desc'     => clean_text(isset($r['desc']) ? $r['desc'] : '', 300),
        'remark'   => clean_remark(isset($r['remark']) ? $r['remark'] : array())
    );
}

function websites_load() {
    global $G_LOAD_ERROR;
    $rows = array();
    try {
        $st = db()->query('SELECT sid, category, name, url, logo, descr, tags FROM websites ORDER BY sort ASC, id ASC');
        foreach ($st as $r) {
            $n = normalize_site(array(
                'id'       => $r['sid'],
                'category' => $r['category'],
                'name'     => $r['name'],
                'url'      => $r['url'],
                'logo'     => $r['logo'],
                'desc'     => $r['descr'],
                'remark'   => ($r['tags'] === '' ? array() : explode(',', $r['tags']))
            ));
            if ($n === null) continue;
            if ($n['id'] === '') $n['id'] = new_site_id($rows);
            $rows[] = $n;
        }
    } catch (Exception $e) {
        $G_LOAD_ERROR = 'SQLite 数据读取失败：' . $e->getMessage() . '，可在「系统设置」中从快照恢复。';
        return array();
    }
    return array_values($rows);
}

function categories_load($rows) {
    $cats = array();
    try {
        $st = db()->query('SELECT name FROM categories ORDER BY sort ASC, id ASC');
        foreach ($st as $r) {
            $c = clean_text($r['name'], 30);
            if ($c !== '' && $c !== '全部' && !in_array($c, $cats, true)) $cats[] = $c;
        }
    } catch (Exception $e) {
        $cats = array();
    }
    /* 兼容旧数据：出现但未登记的栏目自动补齐 */
    foreach ($rows as $r) {
        if (!in_array($r['category'], $cats, true)) $cats[] = $r['category'];
    }
    if (!$cats) $cats = array('未分类');
    return array_values($cats);
}

function load_all() {
    $rows = websites_load();
    return array($rows, categories_load($rows));
}

function find_index($rows, $id) {
    foreach ($rows as $i => $r) if ($r['id'] === $id) return $i;
    return -1;
}

/** 每次修改前保存「修改前」的完整数据库副本，可一键回滚 */
function snapshot_save($rows = null, $cats = null) {
    ensure_dirs();
    $name = 'snapshot-' . date('Ymd-His') . '-' . substr(random_hex(3), 0, 6) . '.sqlite';
    if (!db_copy_to(BACKUP_DIR . $name)) return '';
    rotate_files('snapshot-*.sqlite', 30);
    return $name;
}

function snapshot_list() {
    $files = glob(BACKUP_DIR . 'snapshot-*.sqlite');
    if (!is_array($files)) return array();
    usort($files, 'compare_mtime_desc');
    $out = array();
    foreach (array_slice($files, 0, 30) as $f) {
        $sites = 0;
        try {
            $p = new PDO('sqlite:' . $f);
            $sites = (int)$p->query('SELECT count(*) FROM websites')->fetchColumn();
            $p = null;
        } catch (Exception $e) { /* 损坏的快照仍列出，但不显示条数 */ }
        $out[] = array(
            'file'  => basename($f),
            'time'  => date('Y-m-d H:i:s', @filemtime($f)),
            'sites' => $sites,
            'bytes' => @filesize($f)
        );
    }
    return $out;
}

/** 统一保存数据 + 可选自动重新生成静态页 */
function persist_all($rows, $cats, $cfg, $msg, $params) {
    if (!db_save_all($rows, $cats)) {
        flash('error', '数据写入失败：请检查 admin/data/nav.sqlite 及所在目录的写入权限');
        redirect($params);
    }
    $extra = '';
    if (!empty($cfg['auto_generate'])) {
        $r = generate_static($rows, $cats, $cfg);
        $extra = $r['ok']
            ? '，静态页面已同步更新（' . $r['file'] . '）'
            : '，但静态页面生成失败：' . $r['error'];
    }
    flash('success', $msg . $extra);
    redirect($params);
}

/* ==================================================================
 * 五、图标：上传、路径校验、SSRF 安全抓取
 * ================================================================== */

function safe_icon_path($logo) {
    $v = str_replace('\\', '/', trim((string)$logo));
    if (!preg_match('#^(?:\./)?ico/[A-Za-z0-9_\-./]+$#', $v)) return '';
    if (strpos($v, '..') !== false || strpos($v, '//') !== false) return '';
    $bn = basename($v);
    if ($bn === '' || $bn[0] === '.') return '';
    if (!preg_match('#\.(png|jpe?g|gif|ico|svg|webp)$#i', $bn)) return '';
    $full = PUBLIC_ROOT . '/' . ltrim(preg_replace('#^\./#', '', $v), '/');
    $real = @realpath($full);
    $base = @realpath(UPLOAD_DIR);
    if ($real === false || $base === false) return '';
    if (strpos($real, $base . DIRECTORY_SEPARATOR) !== 0) return '';
    return $full;
}

/** 通过文件魔数识别真实图片类型，拒绝「改后缀的木马」 */
function detect_image($b, $ctype) {
    if (substr($b, 0, 8) === "\x89PNG\r\n\x1a\n") return 'png';
    if (substr($b, 0, 3) === "\xff\xd8\xff") return 'jpg';
    if (substr($b, 0, 3) === 'GIF') return 'gif';
    if (substr($b, 0, 4) === 'RIFF' && substr($b, 8, 4) === 'WEBP') return 'webp';
    if (substr($b, 0, 4) === "\x00\x00\x01\x00" || substr($b, 0, 4) === "\x00\x00\x02\x00") return 'ico';
    if (preg_match('/^\s*(?:<\?xml[^>]*>\s*)?(?:<!DOCTYPE[^>]*>\s*)?<svg\b/i', substr($b, 0, 512))) return 'svg';
    if (stripos((string)$ctype, 'svg') !== false && stripos(substr($b, 0, 512), '<svg') !== false) return 'svg';
    return '';
}

function svg_is_safe($s) {
    if (preg_match('/<\s*(script|foreignObject|iframe|object|embed|use|image|animate|set|handler|audio|video)\b/i', $s)) return false;
    if (preg_match('/\bon[a-z]+\s*=/i', $s)) return false;
    if (preg_match('/(?:javascript|vbscript)\s*:/i', $s)) return false;
    if (preg_match('/data\s*:\s*text\/html/i', $s)) return false;
    if (preg_match('/(?:href|xlink:href)\s*=\s*["\'][^"\']*(?:https?:)?\/\//i', $s)) return false;
    if (preg_match('/@import|url\(\s*["\']?\s*https?:/i', $s)) return false;
    if (preg_match('/<!ENTITY|<!DOCTYPE|<\?php/i', $s)) return false;
    return true;
}

function icon_upload($file) {
    global $NAV_IMAGE_EXT;
    if (!is_array($file) || !isset($file['error']) || is_array($file['error'])) {
        return array('ok' => false, 'error' => '未接收到上传文件');
    }
    if ((int)$file['error'] !== UPLOAD_ERR_OK) {
        return array('ok' => false, 'error' => '上传失败（错误码 ' . (int)$file['error'] . '）');
    }
    if ((int)$file['size'] <= 0 || (int)$file['size'] > MAX_UPLOAD_SIZE) {
        return array('ok' => false, 'error' => '文件为空或超过 500KB 上限');
    }
    $orig = isset($file['name']) ? (string)$file['name'] : 'icon';
    $ext = strtolower(pathinfo($orig, PATHINFO_EXTENSION));
    if (!in_array($ext, $NAV_IMAGE_EXT, true)) {
        return array('ok' => false, 'error' => '仅支持 PNG / JPG / GIF / ICO / WEBP / SVG 图片');
    }
    $tmp = isset($file['tmp_name']) ? (string)$file['tmp_name'] : '';
    if ($tmp === '' || !is_uploaded_file($tmp)) return array('ok' => false, 'error' => '非法上传请求');
    $bytes = @file_get_contents($tmp, false, null, 0, MAX_UPLOAD_SIZE + 1);
    if ($bytes === false || strlen($bytes) > MAX_UPLOAD_SIZE) {
        return array('ok' => false, 'error' => '文件读取失败或超过大小上限');
    }
    $real = detect_image($bytes, '');
    if ($real === '') return array('ok' => false, 'error' => '文件内容不是有效的图片');
    if ($real === 'svg' && !svg_is_safe($bytes)) return array('ok' => false, 'error' => 'SVG 含脚本或外部引用，出于安全考虑已拒绝');
    if ($real === 'svg' && $ext !== 'svg') return array('ok' => false, 'error' => '文件类型与扩展名不一致');
    if ($real !== 'svg' && $ext === 'svg') return array('ok' => false, 'error' => '文件类型与扩展名不一致');
    $canon = $real;
    $base = preg_replace('/[^A-Za-z0-9_\-]/', '-', pathinfo($orig, PATHINFO_FILENAME));
    $base = substr(trim((string)$base, '-'), 0, 36);
    if ($base === '') $base = 'icon';
    $name = $base . '-' . substr(random_hex(4), 0, 8) . '.' . $canon;
    $dest = UPLOAD_DIR . $name;
    ensure_dirs();
    if (!@move_uploaded_file($tmp, $dest)) return array('ok' => false, 'error' => '保存失败，请检查 ico/ 目录权限');
    @chmod($dest, 0644);
    return array('ok' => true, 'path' => './ico/' . $name, 'filename' => $name);
}

function host_public_ips($host) {
    $host = trim((string)$host, '[]');
    $ips = array();
    if (filter_var($host, FILTER_VALIDATE_IP)) {
        $ips[] = $host;
    } else {
        if (!preg_match('/^[A-Za-z0-9\.\-]+$/', $host)) return array();
        $flags = defined('DNS_A') ? constant('DNS_A') : 1;
        if (defined('DNS_AAAA')) $flags |= constant('DNS_AAAA');
        if (function_exists('dns_get_record')) {
            $recs = @dns_get_record($host, $flags);
            if (is_array($recs)) {
                foreach ($recs as $r) {
                    if (!empty($r['ip'])) $ips[] = $r['ip'];
                    if (!empty($r['ipv6'])) $ips[] = $r['ipv6'];
                }
            }
        }
        $ip4 = @gethostbyname($host);
        if ($ip4 && $ip4 !== $host && filter_var($ip4, FILTER_VALIDATE_IP)) $ips[] = $ip4;
    }
    $ips = array_unique($ips);
    $good = array();
    foreach ($ips as $ip) {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) return array();
        $good[] = $ip;
    }
    return array_values($good);
}

/** 仅允许公网 http/https，禁止内网、回环、保留地址与凭据型 URL */
function url_is_safe($url) {
    $p = @parse_url($url);
    if (!is_array($p) || empty($p['scheme']) || empty($p['host'])) return false;
    $s = strtolower($p['scheme']);
    if ($s !== 'http' && $s !== 'https') return false;
    if (isset($p['user']) || isset($p['pass'])) return false;
    if (preg_match('/[\x00-\x20\x7F]/', $url)) return false;
    return count(host_public_ips($p['host'])) > 0;
}

function resolve_url($base, $rel) {
    $rel = trim((string)$rel);
    if ($rel === '') return '';
    if (preg_match('#^https?://#i', $rel)) return $rel;
    $p = @parse_url($base);
    if (!is_array($p)) return '';
    $origin = $p['scheme'] . '://' . $p['host'] . (isset($p['port']) ? ':' . $p['port'] : '');
    if (strpos($rel, '//') === 0) return $p['scheme'] . ':' . $rel;
    if (strpos($rel, '/') === 0) return $origin . $rel;
    $path = isset($p['path']) ? $p['path'] : '/';
    $dir = preg_replace('#/[^/]*$#', '/', $path);
    return $origin . $dir . preg_replace('#^\./#', '', $rel);
}

function header_value($headers, $name) {
    foreach ($headers as $line) {
        $pos = strpos($line, ':');
        if ($pos === false) continue;
        if (strcasecmp(trim(substr($line, 0, $pos)), $name) === 0) return trim(substr($line, $pos + 1));
    }
    return '';
}

/** 不跟随自动跳转（逐跳校验），限制协议、大小、超时，并锁定已校验的 IP */
function http_get($url, $maxBytes, $maxRedirects) {
    if (!function_exists('curl_init')) return array('ok' => false, 'error' => '服务器未启用 cURL，请手动上传图标');
    $current = $url;
    for ($hop = 0; $hop <= $maxRedirects; $hop++) {
        if (!url_is_safe($current)) return array('ok' => false, 'error' => '目标地址不允许访问（仅限公网 HTTP/HTTPS）');
        $p = @parse_url($current);
        $port = isset($p['port']) ? (int)$p['port'] : (strtolower($p['scheme']) === 'https' ? 443 : 80);
        $resolve = array();
        foreach (host_public_ips($p['host']) as $ip) {
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $resolve[] = $p['host'] . ':' . $port . ':' . $ip;
                break;
            }
        }
        $headers = array();
        $body = '';
        $abort = false;
        $ch = curl_init();
        $opts = array(
            CURLOPT_URL            => $current,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER         => false,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT        => 8,
            CURLOPT_CONNECTTIMEOUT => 4,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_USERAGENT      => 'Mozilla/5.0 (compatible; NavAdmin/1.0)',
            CURLOPT_ENCODING       => '',
            CURLOPT_HEADERFUNCTION => function ($c, $line) use (&$headers) {
                $headers[] = $line;
                return strlen($line);
            },
            CURLOPT_WRITEFUNCTION => function ($c, $chunk) use (&$body, &$abort, $maxBytes) {
                if (strlen($body) + strlen($chunk) > $maxBytes) { $abort = true; return 0; }
                $body .= $chunk;
                return strlen($chunk);
            }
        );
        curl_setopt_array($ch, $opts);
        $proto = 0;
        if (defined('CURLPROTO_HTTP')) $proto |= constant('CURLPROTO_HTTP');
        if (defined('CURLPROTO_HTTPS')) $proto |= constant('CURLPROTO_HTTPS');
        /* PHP 8.3+ 推荐字符串形式，旧版回退到位掩码 */
        if (defined('CURLOPT_PROTOCOLS_STR')) {
            @curl_setopt($ch, CURLOPT_PROTOCOLS_STR, 'http,https');
        } elseif ($proto && defined('CURLOPT_PROTOCOLS')) {
            @curl_setopt($ch, CURLOPT_PROTOCOLS, $proto);
        }
        if ($resolve && defined('CURLOPT_RESOLVE')) @curl_setopt($ch, CURLOPT_RESOLVE, $resolve);
        @curl_exec($ch);
        $code = (int)@curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $ctype = (string)@curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
        $errno = @curl_errno($ch);
        curl_close($ch);
        if ($abort) return array('ok' => false, 'error' => '目标响应过大，已中止');
        if ($code >= 300 && $code < 400) {
            $loc = header_value($headers, 'Location');
            if ($loc === '') return array('ok' => false, 'error' => '目标返回了无效的跳转');
            $next = resolve_url($current, $loc);
            if ($next === '' || !url_is_safe($next)) return array('ok' => false, 'error' => '跳转目标不允许访问');
            $current = $next;
            continue;
        }
        if ($errno !== 0 && $code !== 200) return array('ok' => false, 'error' => '无法连接目标站点');
        if ($code !== 200 || $body === '') return array('ok' => false, 'error' => '未获取到图标（HTTP ' . $code . '）');
        return array('ok' => true, 'body' => $body, 'content_type' => $ctype, 'url' => $current);
    }
    return array('ok' => false, 'error' => '跳转次数过多，已中止');
}

function icon_fetch($rawUrl) {
    $url = clean_url($rawUrl);
    if ($url === '') return array('ok' => false, 'error' => '请输入有效的网址');
    if (!url_is_safe($url)) return array('ok' => false, 'error' => '该网址不在允许访问的公网范围内');
    $p = @parse_url($url);
    $origin = $p['scheme'] . '://' . $p['host'] . (isset($p['port']) ? ':' . $p['port'] : '');
    $got = null;
    foreach (array($origin . '/favicon.ico', $origin . '/favicon.png') as $candidate) {
        $r = http_get($candidate, MAX_ICON_SIZE, 2);
        if ($r['ok'] && detect_image($r['body'], $r['content_type']) !== '') { $got = $r; break; }
    }
    if ($got === null) {
        $home = http_get($url, 128 * 1024, 2);
        if ($home['ok'] && preg_match_all('/<link\b[^>]*>/i', $home['body'], $mm)) {
            foreach ($mm[0] as $tag) {
                if (!preg_match('/rel\s*=\s*["\'][^"\']*icon[^"\']*["\']/i', $tag)) continue;
                if (!preg_match('/href\s*=\s*["\']([^"\']+)["\']/i', $tag, $hm)) continue;
                $href = html_entity_decode($hm[1], ENT_QUOTES, 'UTF-8');
                $ico = resolve_url($url, $href);
                if ($ico === '' || !url_is_safe($ico)) continue;
                $r = http_get($ico, MAX_ICON_SIZE, 2);
                if ($r['ok'] && detect_image($r['body'], $r['content_type']) !== '') { $got = $r; break; }
            }
        }
    }
    if ($got === null) return array('ok' => false, 'error' => '未能自动获取图标，请手动上传');
    $ext = detect_image($got['body'], $got['content_type']);
    if ($ext === 'svg' && !svg_is_safe($got['body'])) {
        return array('ok' => false, 'error' => '目标图标包含不安全代码，已拒绝保存');
    }
    $host = preg_replace('/[^A-Za-z0-9\.\-]/', '-', $p['host']);
    $name = substr($host, 0, 36) . '-' . substr(random_hex(4), 0, 8) . '.' . $ext;
    ensure_dirs();
    if (!atomic_write(UPLOAD_DIR . $name, $got['body'])) {
        return array('ok' => false, 'error' => '保存图标失败，请检查 ico/ 目录权限');
    }
    return array('ok' => true, 'path' => './ico/' . $name, 'filename' => $name);
}

/* ==================================================================
 * 六、静态页面生成（数据内嵌 + CSP 哈希）
 * ================================================================== */

/** 供 <script> 内嵌的 JSON：转义 < > & ' " 与 U+2028/U+2029，杜绝脚本逃逸 */
function json_for_html($data) {
    $flags = JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT;
    if (defined('JSON_INVALID_UTF8_SUBSTITUTE')) $flags |= constant('JSON_INVALID_UTF8_SUBSTITUTE');
    $json = json_encode($data, $flags);
    if ($json === false) $json = '{"categories":[],"websites":[]}';
    return str_replace(array("\xE2\x80\xA8", "\xE2\x80\xA9"), array('\u2028', '\u2029'), $json);
}

function inline_hashes($html, $tag) {
    $hashes = array();
    if ($tag === 'script') $pattern = '#<script\b(?![^>]*\bsrc=)[^>]*>(.*?)</script>#si';
    else $pattern = '#<style\b[^>]*>(.*?)</style>#si';
    if (preg_match_all($pattern, $html, $m)) {
        foreach ($m[1] as $code) {
            $hashes[] = "'sha256-" . base64_encode(hash('sha256', $code, true)) . "'";
        }
    }
    return $hashes;
}

function build_csp($html, $mode) {
    $scripts = inline_hashes($html, 'script');
    $styles = inline_hashes($html, 'style');
    $p = array();
    $p[] = "default-src 'self'";
    $p[] = "script-src 'self' " . implode(' ', $scripts);
    $p[] = "style-src 'self' " . implode(' ', $styles);
    $p[] = "img-src 'self' data: https: http:";
    $p[] = "font-src 'self'";
    $p[] = ($mode === 'meta') ? "connect-src 'none'" : "connect-src 'self'";
    $p[] = ($mode === 'meta') ? "form-action 'none'" : "form-action 'self'";
    $p[] = ($mode === 'meta') ? "base-uri 'none'" : "base-uri 'self'";
    $p[] = "object-src 'none'";
    $p[] = "frame-src 'none'";
    $p[] = "child-src 'none'";
    $p[] = "worker-src 'none'";
    $p[] = "media-src 'none'";
    $p[] = "manifest-src 'none'";
    if ($mode !== 'meta') $p[] = "frame-ancestors 'none'";
    return implode('; ', $p);
}

function generate_static($rows, $cats, $cfg) {
    $tpl = @file_get_contents(TEMPLATE_FILE);
    if ($tpl === false || strpos($tpl, '__NAV_DATA_JSON__') === false) {
        return array('ok' => false, 'error' => '模板 admin/template.html 缺失或占位符被破坏');
    }
    $export = array();
    foreach ($rows as $r) {
        $export[] = array(
            'category' => $r['category'], 'name' => $r['name'], 'url' => $r['url'],
            'logo' => $r['logo'], 'desc' => $r['desc'], 'remark' => $r['remark']
        );
    }
    $payload = array('categories' => array_values($cats), 'websites' => $export);
    $html = str_replace(
        array('__NAV_DATA_JSON__', '__GENERATED_AT__', '__SITE_TITLE__'),
        array(json_for_html($payload), date('Y-m-d H:i:s'), h($cfg['site_title'])),
        $tpl
    );
    $html = str_replace('__CSP__', build_csp($html, 'meta'), $html);
    $file = output_filename($cfg);
    $out = PUBLIC_ROOT . '/' . $file;
    backup_existing($out, 'index');
    if (!atomic_write($out, $html)) {
        return array('ok' => false, 'error' => '静态页写入失败，请检查 public/ 目录写权限');
    }
    return array('ok' => true, 'file' => $file, 'bytes' => strlen($html), 'time' => date('Y-m-d H:i:s'));
}

/* ==================================================================
 * 七、请求处理
 * ================================================================== */

function send_json($arr) {
    header('Content-Type: application/json; charset=UTF-8');
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('X-Content-Type-Options: nosniff');
    echo json_encode($arr, JSON_UNESCAPED_UNICODE);
    exit;
}

function site_from_post() {
    $errors = array();
    $cat = post('category');
    if ($cat === '__new__') $cat = post('new_category');
    $cat = clean_category($cat);
    if ($cat === '') $errors[] = '请选择或填写有效的栏目名称';

    $name = clean_text(post('name'), 100);
    if ($name === '') $errors[] = '名称不能为空';

    $url = clean_url(post('url'));
    if ($url === '') $errors[] = 'URL 无效（仅支持 http/https）';

    $logo = clean_logo(post('logo'));
    if ($logo === '') $errors[] = '图标路径无效（请使用 ico/ 下的图片或 http(s) 图片地址）';

    $desc = clean_text(post('desc'), 300);
    if ($desc === '') $errors[] = '描述不能为空';

    $remark = (isset($_POST['remark']) && is_array($_POST['remark']))
        ? clean_remark($_POST['remark']) : array();

    if ($errors) return array('ok' => false, 'errors' => $errors);
    return array('ok' => true, 'item' => array(
        'id' => '', 'category' => $cat, 'name' => $name, 'url' => $url,
        'logo' => $logo, 'desc' => $desc, 'remark' => $remark
    ));
}

function handle_post($action, $cfg, $logged) {
    if (!csrf_valid()) {
        if (is_ajax()) send_json(array('ok' => false, 'error' => '请求已过期，请刷新页面后重试'));
        flash('error', '安全校验失败，请刷新页面后重试');
        redirect();
    }

    /* 首次安装 */
    if ($cfg === null) {
        if ($action === 'install') {
            $pw = post('password');
            $pw2 = post('password2');
            if (strlen($pw) < 8 || strlen($pw) > 200) { flash('error', '密码长度需在 8～200 位之间'); redirect(); }
            if ($pw !== $pw2) { flash('error', '两次输入的密码不一致'); redirect(); }
            $new = config_defaults();
            $new['password_hash'] = password_hash_new($pw);
            $new['default_password'] = false;
            $title = clean_text(post('site_title'), 60);
            if ($title !== '') $new['site_title'] = $title;
            if (!config_save($new)) { flash('error', '数据库写入失败，请检查 admin/data 目录权限'); redirect(); }
            session_regenerate_id(true);
            $_SESSION['logged_in'] = true;
            $_SESSION['login_time'] = time();
            $_SESSION['last_activity'] = time();
            $_SESSION['ua_hash'] = ua_hash();
            $_SESSION['csrf'] = random_hex(32);
            throttle_reset();
            flash('success', '安装完成，请牢记管理员密码');
            redirect(array('tab' => 'generate'));
        }
        redirect();
    }

    /* 登录 */
    if (!$logged) {
        if ($action === 'login') {
            $wait = throttle_locked_seconds();
            if ($wait > 0) {
                flash('error', '尝试次数过多，请在 ' . ceil($wait / 60) . ' 分钟后重试');
                redirect();
            }
            if (password_check(post('password'), $cfg['password_hash'])) {
                throttle_reset();
                session_regenerate_id(true);
                $_SESSION['logged_in'] = true;
                $_SESSION['login_time'] = time();
                $_SESSION['last_activity'] = time();
                $_SESSION['ua_hash'] = ua_hash();
                $_SESSION['csrf'] = random_hex(32);
                flash('success', '登录成功，欢迎回来');
                redirect(array('tab' => 'sites'));
            }
            throttle_fail();
            flash('error', '密码错误');
        }
        redirect();
    }

    /* 以下操作均要求已登录 */
    switch ($action) {
        case 'logout':
            clear_login('已安全退出');
            redirect();
            break;

        case 'fetch_icon':
            send_json(icon_fetch(post('url')));
            break;

        case 'upload_icon':
            $r = icon_upload(isset($_FILES['image']) ? $_FILES['image'] : null);
            if ($r['ok']) {
                $_SESSION['last_icon'] = $r['path'];
                flash('success', '图标已上传：' . $r['path'] . '（已自动填入 Logo 输入框）');
            } else {
                flash('error', $r['error']);
            }
            redirect(array('tab' => 'sites', 'edit' => post('edit_id')));
            break;

        case 'save_site': {
            list($rows, $cats) = load_all();
            snapshot_save($rows, $cats);
            $parsed = site_from_post();
            $editId = post('id');
            $back = array('tab' => 'sites', 'edit' => $editId);
            if (!$parsed['ok']) {
                flash('error', implode('；', $parsed['errors']));
                redirect($back);
            }
            $item = $parsed['item'];
            if (!in_array($item['category'], $cats, true)) $cats[] = $item['category'];
            if ($editId !== '') {
                $idx = find_index($rows, $editId);
                if ($idx < 0) { flash('error', '该条目已不存在，可能已被删除'); redirect($back); }
                $item['id'] = $editId;
                $rows[$idx] = $item;
                $msg = '已保存修改：' . $item['name'];
            } else {
                $item['id'] = new_site_id($rows);
                $pos = count($rows);
                for ($i = count($rows) - 1; $i >= 0; $i--) {
                    if ($rows[$i]['category'] === $item['category']) { $pos = $i + 1; break; }
                }
                array_splice($rows, $pos, 0, array($item));
                $msg = '已添加网址：' . $item['name'];
                unset($_SESSION['last_icon']);
            }
            persist_all($rows, $cats, $cfg, $msg, array('tab' => 'sites'));
            break;
        }

        case 'delete_site': {
            list($rows, $cats) = load_all();
            $idx = find_index($rows, post('id'));
            if ($idx < 0) { flash('error', '条目不存在'); redirect(array('tab' => 'sites')); }
            snapshot_save($rows, $cats);
            $old = $rows[$idx];
            array_splice($rows, $idx, 1);
            $note = '';
            if (post('del_icon') === '1') {
                $path = safe_icon_path($old['logo']);
                if ($path !== '' && is_file($path)) {
                    $used = false;
                    foreach ($rows as $r) {
                        if ($r['logo'] === $old['logo'] || safe_icon_path($r['logo']) === $path) { $used = true; break; }
                    }
                    if (!$used) {
                        $note = @unlink($path) ? '，并清理了未再使用的图标文件' : '，图标文件清理失败（权限不足）';
                    }
                }
            }
            persist_all($rows, $cats, $cfg, '已删除：' . $old['name'] . $note, array('tab' => 'sites'));
            break;
        }

        case 'move_site': {
            list($rows, $cats) = load_all();
            $idx = find_index($rows, post('id'));
            if ($idx < 0) { flash('error', '条目不存在'); redirect(array('tab' => 'sites')); }
            $dir = post('dir') === 'up' ? -1 : 1;
            $cat = $rows[$idx]['category'];
            $positions = array();
            foreach ($rows as $i => $r) if ($r['category'] === $cat) $positions[] = $i;
            $p = array_search($idx, $positions, true);
            $target = $p + $dir;
            if ($p === false || $target < 0 || $target >= count($positions)) {
                flash('error', '已经到边界了');
                redirect(array('tab' => 'sites'));
            }
            snapshot_save($rows, $cats);
            $j = $positions[$target];
            $tmp = $rows[$idx]; $rows[$idx] = $rows[$j]; $rows[$j] = $tmp;
            persist_all($rows, $cats, $cfg, '排序已更新', array('tab' => 'sites'));
            break;
        }

        case 'save_category': {
            list($rows, $cats) = load_all();
            $old = post('cat_id');
            $name = clean_category(post('name'));
            if ($name === '') { flash('error', '栏目名称无效（不能含 < > " \' / \\ 等字符）'); redirect(array('tab' => 'categories')); }
            snapshot_save($rows, $cats);
            if ($old === '') {
                if (in_array($name, $cats, true)) { flash('error', '该栏目已存在'); redirect(array('tab' => 'categories')); }
                $cats[] = $name;
                $msg = '已新增栏目：' . $name;
            } else {
                $i = array_search($old, $cats, true);
                if ($i === false) { flash('error', '栏目不存在'); redirect(array('tab' => 'categories')); }
                if ($name !== $old && in_array($name, $cats, true)) { flash('error', '目标栏目名已被占用'); redirect(array('tab' => 'categories')); }
                $cats[$i] = $name;
                foreach ($rows as $k => $r) if ($r['category'] === $old) $rows[$k]['category'] = $name;
                $msg = '栏目已更新：' . $old . ' → ' . $name;
            }
            persist_all($rows, $cats, $cfg, $msg, array('tab' => 'categories'));
            break;
        }

        case 'delete_category': {
            list($rows, $cats) = load_all();
            $name = post('cat_id');
            $i = array_search($name, $cats, true);
            if ($i === false) { flash('error', '栏目不存在'); redirect(array('tab' => 'categories')); }
            $move = post('move_to');
            if ($move === '__uncategorized__') $move = '未分类';
            else $move = clean_category($move);
            $affected = 0;
            foreach ($rows as $r) if ($r['category'] === $name) $affected++;
            if ($affected > 0) {
                if ($move === '' || $move === $name) { flash('error', '该栏目下还有网址，请选择迁移目标栏目'); redirect(array('tab' => 'categories')); }
                if ($move === '未分类' && !in_array('未分类', $cats, true)) $cats[] = '未分类';
                if (!in_array($move, $cats, true)) { flash('error', '迁移目标栏目不存在'); redirect(array('tab' => 'categories')); }
            }
            snapshot_save($rows, $cats);
            foreach ($rows as $k => $r) if ($r['category'] === $name) $rows[$k]['category'] = $move;
            unset($cats[$i]);
            $cats = array_values($cats);
            $msg = '已删除栏目：' . $name . ($affected > 0 ? '，' . $affected . ' 条网址已迁移到「' . $move . '」' : '');
            persist_all($rows, $cats, $cfg, $msg, array('tab' => 'categories'));
            break;
        }

        case 'move_category': {
            list($rows, $cats) = load_all();
            $name = post('cat_id');
            $i = array_search($name, $cats, true);
            $j = $i + (post('dir') === 'up' ? -1 : 1);
            if ($i === false || $j < 0 || $j >= count($cats)) { flash('error', '已经到边界了'); redirect(array('tab' => 'categories')); }
            snapshot_save($rows, $cats);
            $tmp = $cats[$i]; $cats[$i] = $cats[$j]; $cats[$j] = $tmp;
            persist_all($rows, $cats, $cfg, '栏目顺序已更新', array('tab' => 'categories'));
            break;
        }

        case 'generate': {
            list($rows, $cats) = load_all();
            $r = generate_static($rows, $cats, $cfg);
            if ($r['ok']) {
                flash('success', '静态页面已生成：' . $r['file'] . '（' . number_format($r['bytes'] / 1024, 1) . ' KB）');
            } else {
                flash('error', '生成失败：' . $r['error']);
            }
            redirect(array('tab' => 'generate'));
            break;
        }

        case 'save_settings': {
            $title = clean_text(post('site_title'), 60);
            $out = post('output_file');
            if (!preg_match('/^[A-Za-z0-9_\-]+\.html$/', $out)) $out = 'index.html';
            $idle = (int)post('session_idle');
            if ($idle < 300 || $idle > 86400) $idle = 1800;
            $new = $cfg;
            $new['site_title'] = $title === '' ? '网址导航' : $title;
            $new['output_file'] = $out;
            $new['session_idle'] = $idle;
            $new['auto_generate'] = post('auto_generate') === '1';
            if (!config_save($new)) { flash('error', '设置写入失败，请检查数据库权限'); redirect(array('tab' => 'settings')); }
            if ($new['site_title'] !== $cfg['site_title'] || $new['output_file'] !== $cfg['output_file']) {
                list($rows, $cats) = load_all();
                generate_static($rows, $cats, $new);
            }
            flash('success', '设置已保存');
            redirect(array('tab' => 'settings'));
            break;
        }

        case 'change_password': {
            if (!password_check(post('current_password'), $cfg['password_hash'])) {
                flash('error', '当前密码不正确'); redirect(array('tab' => 'settings'));
            }
            $pw = post('new_password');
            if (strlen($pw) < 8 || strlen($pw) > 200) { flash('error', '新密码长度需在 8～200 位之间'); redirect(array('tab' => 'settings')); }
            if ($pw !== post('new_password2')) { flash('error', '两次输入的新密码不一致'); redirect(array('tab' => 'settings')); }
            if (password_check($pw, $cfg['password_hash'])) { flash('error', '新密码不能与当前密码相同'); redirect(array('tab' => 'settings')); }
            $new = $cfg;
            $new['password_hash'] = password_hash_new($pw);
            $new['default_password'] = false;
            if (!config_save($new)) { flash('error', '密码写入失败，密码未变更'); redirect(array('tab' => 'settings')); }
            session_regenerate_id(true);
            $_SESSION['last_activity'] = time();
            $_SESSION['csrf'] = random_hex(32);
            flash('success', '密码已更新，请牢记新密码');
            redirect(array('tab' => 'settings'));
            break;
        }

        case 'snapshot': {
            list($rows, $cats) = load_all();
            $f = snapshot_save($rows, $cats);
            flash($f ? 'success' : 'error', $f ? '已创建数据快照：' . $f : '快照创建失败，请检查 admin/backup/ 权限');
            redirect(array('tab' => 'settings'));
            break;
        }

        case 'restore': {
            $file = basename(post('file'));
            if (!preg_match('/^snapshot-[0-9]{8}-[0-9]{6}-[0-9a-f]{6}\.sqlite$/', $file)) {
                flash('error', '快照文件名不合法'); redirect(array('tab' => 'settings'));
            }
            $path = BACKUP_DIR . $file;
            if (!is_file($path)) { flash('error', '快照文件不存在'); redirect(array('tab' => 'settings')); }
            snapshot_save();                       /* 恢复前先把当前数据库备份一份 */
            if (!db_restore_from($path)) {
                flash('error', '恢复失败：快照不是有效的 SQLite 数据库，或数据库目录不可写');
                redirect(array('tab' => 'settings'));
            }
            list($rows, $cats) = load_all();
            if (!empty($cfg['auto_generate'])) generate_static($rows, $cats, $cfg);
            flash('success', '已从快照 ' . $file . ' 恢复数据');
            redirect(array('tab' => 'settings'));
            break;
        }

        case 'export_data': {
            ensure_dirs();
            $tmp = BACKUP_DIR . 'export-' . date('Ymd-His') . '-' . substr(random_hex(3), 0, 6) . '.sqlite';
            if (!db_copy_to($tmp)) {
                flash('error', '导出失败：无法复制数据库'); redirect(array('tab' => 'settings'));
            }
            header('Content-Type: application/x-sqlite3');
            header('Content-Disposition: attachment; filename="nav-data-' . date('Ymd-His') . '.sqlite"');
            header('Content-Length: ' . (int)@filesize($tmp));
            header('Cache-Control: no-store');
            header('X-Content-Type-Options: nosniff');
            readfile($tmp);
            @unlink($tmp);
            exit;
        }

        default:
            flash('error', '未知操作');
            redirect();
    }
}

/* ==================================================================
 * 八、页面渲染
 * ================================================================== */

function send_html($html) {
    header('Content-Type: text/html; charset=UTF-8');
    header('Cache-Control: private, no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
    header('Content-Security-Policy: ' . build_csp($html, 'header'));
    echo $html;
}

function admin_css() {
    /* 样式独立存放于 css/admin.css，可直接编辑，无需改动 PHP；
       由后台读取后内联输出，避免额外请求、避免外链被 CSP / 路径问题拦截。
       文件不可读时回退到内置样式，保证后台任何情况下都不会「裸奔」。 */
    $file = ADMIN_CSS_FILE;
    if (is_readable($file)) {
        $css = @file_get_contents($file);
        if ($css !== false && strpos($css, '{') !== false) {
            /* 防止样式文件被误写入 HTML 标签提前闭合 style 块造成注入；
               正常 CSS 不含这些字符串，替换后完全不影响样式规则 */
            return str_ireplace(
                array('</style', '<style', '<script', '</script'),
                array('< /style', '< style', '< script', '< /script'),
                $css
            );
        }
    }
    return <<<'CSS'
* { box-sizing: border-box; }
:root { --brand:#667eea; --brand2:#764ba2; --ink:#2c3e50; --muted:#7b8794; --line:#e6eaf0; --bg:#f4f6fa; --ok:#1a7f4b; --bad:#c0392b; }
body { margin:0; background:var(--bg); color:var(--ink); font:14px/1.6 "Segoe UI",Roboto,"Microsoft YaHei",system-ui,sans-serif; }
a { color:var(--brand); text-decoration:none; }
a:hover { text-decoration:underline; }
.topbar { background:#fff; border-bottom:1px solid var(--line); box-shadow:0 2px 10px rgba(30,50,90,.05); }
.topbar-inner { max-width:1440px; margin:0 auto; padding:10px 22px; display:flex; align-items:center; gap:18px; flex-wrap:wrap; }
.brand { font-size:18px; font-weight:700; background:linear-gradient(135deg,var(--brand),var(--brand2)); -webkit-background-clip:text; background-clip:text; color:transparent; }
.tabs { display:flex; gap:4px; flex-wrap:wrap; }
.tab { padding:7px 15px; border-radius:8px; color:#56637a; font-weight:600; white-space:nowrap; }
.tab:hover { background:#f0f2fb; text-decoration:none; }
.tab.active { background:linear-gradient(135deg,var(--brand),var(--brand2)); color:#fff; }
.logout-form { margin-left:auto; }
.wrap { max-width:1440px; margin:22px auto; padding:0 22px 60px; }
.card { background:#fff; border:1px solid var(--line); border-radius:14px; margin-bottom:18px; box-shadow:0 6px 20px rgba(30,50,90,.05); }
.card-head { padding:16px 22px; border-bottom:1px solid var(--line); display:flex; align-items:center; gap:12px; flex-wrap:wrap; }
.card-head h2 { margin:0; font-size:17px; font-weight:700; }
.card-head .sub { color:var(--muted); font-size:13px; }
.card-body { padding:20px 22px; }
.flash { padding:12px 18px; border-radius:10px; margin-bottom:16px; font-weight:600; }
.flash-success { background:#e5f6ec; color:var(--ok); border-left:5px solid #28a745; }
.flash-error { background:#fdeaea; color:var(--bad); border-left:5px solid #dc3545; }
.notice { padding:12px 18px; border-radius:10px; margin-bottom:16px; }
.notice-warn { background:#fff6e0; color:#8a5a00; border-left:5px solid #f0a500; }
.muted { color:var(--muted); }
.hint { display:block; color:var(--muted); font-size:12px; margin-top:4px; }
.btn { display:inline-flex; align-items:center; justify-content:center; gap:6px; padding:9px 18px; border:1px solid transparent; border-radius:9px; font-size:14px; font-weight:600; cursor:pointer; background:#eef1f7; color:#42506a; font-family:inherit; }
.btn:hover { text-decoration:none; filter:brightness(.97); }
.btn-primary { background:linear-gradient(135deg,var(--brand),var(--brand2)); color:#fff; box-shadow:0 4px 12px rgba(102,126,234,.28); }
.btn-ghost { background:#f1f3f9; border-color:#dfe4ee; color:#45536c; }
.btn-danger { background:#fdecec; border-color:#f5c9c9; color:var(--bad); }
.btn-sm { padding:7px 13px; font-size:13px; }
.btn-xs { padding:4px 9px; font-size:12px; border-radius:7px; }
.btn-block { width:100%; }
.btn:disabled { opacity:.55; cursor:not-allowed; }
.grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:16px 22px; }
.field { display:flex; flex-direction:column; gap:6px; }
.field > label { font-weight:600; color:#45536c; }
.field input[type=text], .field input[type=url], .field input[type=password], .field select, .field textarea {
    width:100%; padding:10px 13px; border:2px solid #dfe4ee; border-radius:9px; font-size:14px; font-family:inherit; line-height:1.5; background:#fff; color:var(--ink);
}
.field input:focus, .field select:focus, .field textarea:focus { border-color:var(--brand); outline:none; box-shadow:0 0 0 3px rgba(102,126,234,.18); }
.field textarea { resize:vertical; min-height:74px; }
.inline-row { display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
.inline-row .grow { flex:1 1 220px; }
.hidden { display:none; }
.mt { margin-top:16px; }
.gap-lg { gap:10px; }
.form-actions.tight { margin-top:0; margin-bottom:16px; }
.checks { display:flex; flex-wrap:wrap; gap:10px 20px; background:#fafbfe; border:1px solid var(--line); border-radius:10px; padding:14px; }
.check { display:inline-flex; align-items:center; gap:6px; cursor:pointer; user-select:none; }
.check input { width:16px; height:16px; }
.check-mini { display:inline-flex; align-items:center; gap:3px; font-size:12px; color:var(--muted); }
.form-actions { display:flex; gap:10px; flex-wrap:wrap; margin-top:18px; }
.toolbar { display:flex; gap:10px; align-items:center; flex-wrap:wrap; }
.toolbar input[type=text], .toolbar select { padding:9px 12px; border:2px solid #dfe4ee; border-radius:9px; font:inherit; }
.toolbar input[type=text] { flex:1 1 240px; }
.count { margin-left:auto; color:var(--muted); font-size:13px; }
.table-wrap { overflow-x:auto; }
table { width:100%; border-collapse:collapse; }
th { background:#f7f9fd; text-align:left; font-weight:700; color:#45536c; padding:10px 10px; border-bottom:2px solid var(--line); white-space:nowrap; }
td { padding:9px 10px; border-bottom:1px solid #eef1f6; vertical-align:middle; }
tr:last-child td { border-bottom:none; }
tbody tr:hover td { background:#fafbff; }
.w-cat { width:110px; } .w-ico { width:52px; } .w-name { width:150px; } .w-tags { width:130px; } .w-ops { width:240px; }
.site-logo { width:32px; height:32px; object-fit:contain; border-radius:6px; background:#f0f2f6; padding:2px; }
.cell-url { display:block; max-width:280px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-size:13px; }
.cell-desc { max-width:330px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.pill { display:inline-block; padding:2px 9px; border-radius:20px; background:#edf2ff; color:#4a5dbb; font-size:12px; white-space:nowrap; }
.tag { display:inline-block; padding:1px 6px; margin:1px 2px 1px 0; border-radius:5px; background:#f0f2f6; color:#65708a; font-size:11px; }
.actions { white-space:nowrap; }
.inline-form { display:inline-flex; align-items:center; gap:4px; margin:0; vertical-align:middle; }
.inline-form input[type=text] { width:150px; padding:6px 9px; border:2px solid #dfe4ee; border-radius:7px; font:inherit; }
.inline-form select { max-width:140px; padding:5px 7px; border:1px solid #dfe4ee; border-radius:7px; font:inherit; font-size:12px; }
.stack { display:flex; flex-direction:column; gap:6px; }
.pager { display:flex; gap:6px; align-items:center; flex-wrap:wrap; margin-top:16px; }
.pager a { padding:5px 11px; border:1px solid var(--line); border-radius:7px; background:#fff; }
.pager .cur { padding:5px 11px; border-radius:7px; background:var(--brand); color:#fff; }
.pager .info { color:var(--muted); margin-right:auto; }
.kv { display:grid; grid-template-columns:repeat(auto-fit,minmax(240px,1fr)); gap:10px 22px; margin:0; }
.kv > div { padding:9px 12px; border-radius:9px; background:#f8faff; border:1px solid var(--line); }
.kv b { display:block; font-size:12px; color:var(--muted); font-weight:600; }
.kv span { font-weight:600; word-break:break-all; }
.badge { display:inline-block; padding:2px 9px; border-radius:20px; font-size:12px; font-weight:700; }
.badge-ok { background:#e5f6ec; color:var(--ok); }
.badge-warn { background:#fff1d6; color:#8a5a00; }
.badge-bad { background:#fdeaea; color:var(--bad); }
.logo-preview img { max-width:34px; max-height:34px; border-radius:6px; background:#f0f2f6; padding:2px; }
.upload-form { display:flex; align-items:center; gap:10px; flex-wrap:wrap; }
.upload-form input[type=file] { padding:8px; border:1px dashed var(--brand); border-radius:8px; background:#fff; }
.split { display:grid; grid-template-columns:repeat(auto-fit,minmax(320px,1fr)); gap:18px; }
.login-wrap { min-height:100vh; display:flex; align-items:center; justify-content:center; padding:24px; background:linear-gradient(135deg,#667eea,#764ba2); }
.login-card { width:100%; max-width:390px; background:rgba(255,255,255,.97); padding:34px; border-radius:16px; box-shadow:0 16px 50px rgba(20,30,60,.25); }
.login-card h1 { margin:0 0 6px; font-size:24px; font-weight:700; }
.login-card .lead { margin:0 0 22px; color:var(--muted); font-size:13px; }
.login-card .field { margin-bottom:16px; }
.empty { padding:26px; text-align:center; color:var(--muted); }
.file-list { display:flex; flex-direction:column; gap:7px; }
.file-row { display:flex; gap:10px; align-items:center; flex-wrap:wrap; padding:9px 12px; border:1px solid var(--line); border-radius:9px; background:#fafbfe; }
.file-row .name { font-family:Consolas,monospace; font-size:12px; }
.file-row .grow { flex:1; }
@media (max-width:760px) { .topbar-inner { padding:10px 14px; } .wrap { padding:0 12px 40px; } .logout-form { margin-left:0; } .count { margin-left:0; } .cell-desc { max-width:180px; } }
CSS;
}

function admin_js() {
    return <<<'JS'
'use strict';
var CSRF = '__CSRF_TOKEN__';
var PUBLIC_BASE = __PUBLIC_BASE__;
var DEFAULT_ICON = __DEFAULT_ICON__;

/* 图标统一按 public/ 的绝对 Web 路径解析：后台入口放在哪个目录都不会 404 */
function iconUrl(v) {
    v = String(v || '').trim().replace(/\\/g, '/');
    if (/^https?:\/\//i.test(v)) return v;
    v = v.replace(/^\.\//, '').replace(/^\//, '');
    if (v.indexOf('..') !== -1 || !/^ico\/[A-Za-z0-9_\-./]+$/.test(v)) return DEFAULT_ICON;
    return PUBLIC_BASE + v;
}

/* 所有危险操作统一确认，避免使用内联 onclick */
document.addEventListener('submit', function (e) {
    var f = e.target;
    if (f && f.getAttribute && f.getAttribute('data-confirm')) {
        if (!window.confirm(f.getAttribute('data-confirm'))) e.preventDefault();
    }
}, false);

/* 新建栏目输入显隐 */
var catSelect = document.querySelector('[data-cat-select]');
if (catSelect) {
    var newCat = document.querySelector('[data-new-cat]');
    catSelect.addEventListener('change', function () {
        if (!newCat) return;
        var on = this.value === '__new__';
        newCat.classList.toggle('hidden', !on);
        newCat.required = on;
        if (on) newCat.focus();
    });
}

/* 图标预览 + 失败回退（不使用内联事件，兼容严格 CSP） */
var logoInput = document.querySelector('[data-logo-input]');
var logoBox = document.querySelector('[data-logo-preview]');
function showLogo(v) {
    if (!logoBox) return;
    if (!v) { logoBox.classList.add('hidden'); return; }
    var img = logoBox.querySelector('img');
    if (!img) { img = document.createElement('img'); img.alt = '图标预览'; logoBox.appendChild(img); }
    img.src = iconUrl(v);
    logoBox.classList.remove('hidden');
}
if (logoInput) {
    logoInput.addEventListener('input', function () { showLogo(this.value.trim()); });
    if (logoInput.value.trim()) showLogo(logoInput.value.trim());
}
document.addEventListener('error', function (e) {
    var el = e.target;
    if (el && el.tagName === 'IMG' && el.getAttribute('data-fallback') !== '1') {
        el.setAttribute('data-fallback', '1');
        el.src = DEFAULT_ICON;
    }
}, true);

/* 自动获取网站图标：POST + CSRF，服务端做 SSRF 防护 */
var fetchBtn = document.querySelector('[data-fetch-icon]');
var urlInput = document.querySelector('[data-site-url]');
function fetchIcon(quiet) {
    if (!urlInput) return;
    var url = urlInput.value.trim();
    if (!url) { if (!quiet) window.alert('请先填写 URL'); return; }
    if (fetchBtn) { fetchBtn.disabled = true; fetchBtn.textContent = '获取中…'; }
    var body = 'action=fetch_icon&ajax=1&csrf_token=' + encodeURIComponent(CSRF) + '&url=' + encodeURIComponent(url);
    fetch(window.location.pathname, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-CSRF-Token': CSRF, 'X-Requested-With': 'fetch' },
        body: body
    }).then(function (r) { return r.json(); }).then(function (d) {
        if (d && d.ok && logoInput) { logoInput.value = d.path; showLogo(d.path); }
        else if (!quiet) { window.alert('获取图标失败：' + ((d && d.error) || '未知错误')); }
    }).catch(function () {
        if (!quiet) window.alert('网络错误，请稍后重试');
    }).then(function () {
        if (fetchBtn) { fetchBtn.disabled = false; fetchBtn.textContent = '获取图标'; }
    });
}
if (fetchBtn) fetchBtn.addEventListener('click', function () { fetchIcon(false); });
if (urlInput) {
    var autoDone = false;
    urlInput.addEventListener('blur', function () {
        if (autoDone || !logoInput || logoInput.value.trim()) return;
        if (urlInput.value.trim()) { autoDone = true; fetchIcon(true); }
    });
}
JS;
}

function render_shell($title, $body, $cfg, $chrome) {
    $f = take_flash();
    $fh = '';
    if (is_array($f)) {
        $type = $f['type'] === 'error' ? 'error' : 'success';
        $fh = '<div class="flash flash-' . $type . '">' . h($f['msg']) . '</div>';
    }
    /* 外链样式表（可缓存） + 同源内联样式（兜底）。
       部分服务器会用全局 CSP 覆盖 PHP 响应头，可能只允许外链或只允许内联；
       两条路径并存可保证任何环境下后台都有完整样式。 */
    $cssLink = '';
    if (is_readable(ADMIN_CSS_FILE)) {
        $cssLink = '<link rel="stylesheet" href="' . h(public_asset_url('css/admin.css')) . '">' . "\n";
    }
    $jsBase = json_encode(public_base_url(), JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES);
    if ($jsBase === false) $jsBase = '"/"';
    $jsIcon = json_encode(default_icon_uri(), JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES);
    if ($jsIcon === false) $jsIcon = '""';
    $js = str_replace(
        array('__CSRF_TOKEN__', '__PUBLIC_BASE__', '__DEFAULT_ICON__'),
        array(csrf_token(), $jsBase, $jsIcon),
        admin_js()
    );
    $html = '<!DOCTYPE html>' . "\n"
          . '<html lang="zh-CN"><head><meta charset="UTF-8">' . "\n"
          . '<meta name="viewport" content="width=device-width, initial-scale=1.0">' . "\n"
          . '<meta name="robots" content="noindex,nofollow,noarchive">' . "\n"
          . '<meta name="referrer" content="no-referrer">' . "\n"
          . '<title>' . h($title) . '</title>' . "\n"
          . $cssLink
          . '<!-- 后台样式取自 css/admin.css，另内联一份作为兜底，避免外链或 CSP 环境差异导致无样式 -->' . "\n"
          . '<style>' . admin_css() . '</style>' . "\n"
          . '</head><body>' . "\n"
          . $chrome . "\n"
          . '<main class="wrap">' . $fh . $body . '</main>' . "\n"
          . '<script>' . $js . '</script>' . "\n"
          . '</body></html>';
    send_html($html);
}

function render_install() {
    $body = '<div class="login-wrap"><form class="login-card" method="post">'
          . '<h1>初始化导航后台</h1>'
          . '<p class="lead">首次使用，请设置管理员密码。密码将以 PBKDF2-SHA256 加盐哈希保存，不会明文存储。</p>'
          . csrf_field() . '<input type="hidden" name="action" value="install">'
          . '<div class="field"><label>站点标题</label><input type="text" name="site_title" value="梁老师网址导航" maxlength="60"></div>'
          . '<div class="field"><label>管理员密码（至少 8 位）</label><input type="password" name="password" required autocomplete="new-password"></div>'
          . '<div class="field"><label>确认密码</label><input type="password" name="password2" required autocomplete="new-password"></div>'
          . '<button class="btn btn-primary btn-block" type="submit">完成安装</button>'
          . '</form></div>';
    render_shell('初始化 - 网址导航后台', $body, null, '');
}

function render_login($cfg) {
    $wait = throttle_locked_seconds();
    $notice = $wait > 0
        ? '<div class="notice notice-warn">登录已被临时锁定，请在 ' . ceil($wait / 60) . ' 分钟后重试。</div>' : '';
    $body = '<div class="login-wrap"><form class="login-card" method="post">'
          . '<h1>管理登录</h1>'
          . '<p class="lead">' . h($cfg['site_title']) . ' · 连续 5 次密码错误将锁定 15 分钟</p>'
          . $notice
          . csrf_field() . '<input type="hidden" name="action" value="login">'
          . '<div class="field"><label>管理员密码</label><input type="password" name="password" required autofocus autocomplete="current-password"></div>'
          . '<button class="btn btn-primary btn-block" type="submit"' . ($wait > 0 ? ' disabled' : '') . '>登录</button>'
          . '</form></div>';
    render_shell('登录 - 网址导航后台', $body, $cfg, '');
}

function tabs_html($active) {
    $tabs = array('sites' => '网址管理', 'categories' => '栏目管理', 'generate' => '静态页面', 'settings' => '系统设置');
    $out = '<nav class="tabs">';
    foreach ($tabs as $k => $label) {
        $out .= '<a class="tab' . ($active === $k ? ' active' : '') . '" href="' . h(nav_url(array('tab' => $k))) . '">' . h($label) . '</a>';
    }
    $out .= '</nav>';
    return $out;
}

function chrome_html($cfg, $active) {
    return '<header class="topbar"><div class="topbar-inner">'
         . '<span class="brand">' . h($cfg['site_title']) . ' · 后台</span>'
         . tabs_html($active)
         . '<form class="logout-form" method="post">' . csrf_field()
         . '<input type="hidden" name="action" value="logout">'
         . '<button class="btn btn-ghost btn-sm" type="submit">退出登录</button></form>'
         . '</div></header>';
}

/* ------------------------- 网址管理 ------------------------- */

function site_form_html($cfg, $rows, $cats, $editItem, $editId) {
    $isEdit = is_array($editItem);
    $v = function ($k) use ($editItem, $isEdit) { return $isEdit && isset($editItem[$k]) ? $editItem[$k] : ''; };
    $catVal = $isEdit ? $editItem['category'] : '';
    $logoVal = $v('logo');
    if (!$isEdit && $logoVal === '' && !empty($_SESSION['last_icon'])) $logoVal = $_SESSION['last_icon'];

    $opts = '<option value="">-- 选择栏目 --</option>';
    foreach ($cats as $c) {
        $opts .= '<option value="' . h($c) . '"' . ($catVal === $c ? ' selected' : '') . '>' . h($c) . '</option>';
    }
    $opts .= '<option value="__new__">＋ 新建栏目…</option>';

    $checks = '';
    $cur = $isEdit && is_array($editItem['remark']) ? $editItem['remark'] : array();
    foreach (remark_options() as $k => $label) {
        $checks .= '<label class="check"><input type="checkbox" name="remark[]" value="' . h($k) . '"'
                 . (in_array($k, $cur, true) ? ' checked' : '') . '>' . h($label) . '</label>';
    }

    $body = '<div class="card"><div class="card-head"><h2>' . ($isEdit ? '编辑网址' : '添加网址') . '</h2>'
          . '<span class="sub">保存后' . (!empty($cfg['auto_generate']) ? '会自动重新生成静态页面' : '需到「静态页面」手动生成') . '</span></div>'
          . '<div class="card-body"><form method="post" id="site-form">'
          . csrf_field() . '<input type="hidden" name="action" value="save_site">'
          . ($isEdit ? '<input type="hidden" name="id" value="' . h($editId) . '">' : '')
          . '<div class="grid">'
          . '<div class="field"><label>栏目</label><select name="category" data-cat-select required>' . $opts . '</select>'
          . '<input type="text" name="new_category" data-new-cat class="hidden" placeholder="新栏目名称" maxlength="30"></div>'
          . '<div class="field"><label>名称</label><input type="text" name="name" value="' . h($v('name')) . '" required maxlength="100" placeholder="网站名称"></div>'
          . '<div class="field"><label>网址 URL</label><div class="inline-row">'
          . '<input class="grow" type="url" name="url" data-site-url value="' . h($v('url')) . '" required placeholder="https://example.com">'
          . '<button class="btn btn-ghost btn-sm" type="button" data-fetch-icon>获取图标</button></div>'
          . '<span class="hint">仅接受 http/https；若 Logo 留空，离开输入框时会自动尝试抓取站点图标</span></div>'
          . '<div class="field"><label>Logo 图标</label><div class="inline-row">'
          . '<input class="grow" type="text" name="logo" data-logo-input value="' . h($logoVal) . '" placeholder="./ico/example.png">'
          . '<span class="logo-preview' . ($logoVal === '' ? ' hidden' : '') . '" data-logo-preview>'
          . ($logoVal !== '' ? '<img src="' . h(admin_icon_url($logoVal)) . '" alt="图标预览">' : '') . '</span></div>'
          . '<span class="hint">本地路径需位于 ico/ 目录，也可填写 https 图片地址</span></div>'
          . '</div>'
          . '<div class="field mt"><label>描述</label><textarea name="desc" required maxlength="300" rows="2">' . h($v('desc')) . '</textarea></div>'
          . '<div class="field mt"><label>标签</label><div class="checks">' . $checks . '</div></div>'
          . '<div class="form-actions"><button class="btn btn-primary" type="submit">' . ($isEdit ? '保存修改' : '添加网址') . '</button>'
          . ($isEdit ? '<a class="btn btn-ghost" href="' . h(nav_url(array('tab' => 'sites'))) . '">取消编辑</a>' : '')
          . '</div></form></div></div>';
    return $body;
}

function sites_tab_html($cfg, $rows, $cats) {
    $q = trim(getq('q'));
    $cat = getq('cat');
    $page = max(1, (int)getq('page'));
    $editId = getq('edit');
    $editItem = null;
    if ($editId !== '') {
        $i = find_index($rows, $editId);
        if ($i >= 0) $editItem = $rows[$i];
    }

    $filtered = array();
    foreach ($rows as $i => $r) {
        if ($cat !== '' && $r['category'] !== $cat) continue;
        if ($q !== '' && stripos($r['name'] . ' ' . $r['desc'] . ' ' . $r['url'], $q) === false) continue;
        $filtered[] = array('i' => $i, 'r' => $r);
    }
    $total = count($filtered);
    $pages = max(1, (int)ceil($total / PER_PAGE));
    $page = min($page, $pages);
    $slice = array_slice($filtered, ($page - 1) * PER_PAGE, PER_PAGE);

    $out = site_form_html($cfg, $rows, $cats, $editItem, $editId);

    /* 图标上传 */
    $out .= '<div class="card"><div class="card-head"><h2>上传图标</h2><span class="sub">上传后自动填入上方 Logo 输入框</span></div>'
          . '<div class="card-body"><form class="upload-form" method="post" enctype="multipart/form-data">'
          . csrf_field() . '<input type="hidden" name="action" value="upload_icon">'
          . '<input type="hidden" name="edit_id" value="' . h($editId) . '">'
          . '<input type="file" name="image" accept=".png,.jpg,.jpeg,.gif,.ico,.webp,.svg" required>'
          . '<button class="btn btn-primary btn-sm" type="submit">上传</button>'
          . '<span class="muted">PNG / JPG / GIF / ICO / WEBP / SVG，≤500KB；会校验真实文件内容并重命名</span>'
          . '</form></div></div>';

    /* 搜索栏 */
    $catOpts = '<option value="">全部栏目</option>';
    foreach ($cats as $c) {
        $catOpts .= '<option value="' . h($c) . '"' . ($cat === $c ? ' selected' : '') . '>' . h($c) . '</option>';
    }
    $out .= '<div class="card"><div class="card-head"><h2>网址列表</h2><span class="sub">共 ' . count($rows) . ' 条数据</span></div>'
          . '<div class="card-body"><form class="toolbar" method="get">'
          . '<input type="hidden" name="tab" value="sites">'
          . '<input type="text" name="q" value="' . h($q) . '" placeholder="搜索名称 / 描述 / 网址">'
          . '<select name="cat">' . $catOpts . '</select>'
          . '<button class="btn btn-primary btn-sm" type="submit">筛选</button>'
          . '<a class="btn btn-ghost btn-sm" href="' . h(nav_url(array('tab' => 'sites'))) . '">重置</a>'
          . '<span class="count">匹配 ' . $total . ' 条 · 第 ' . $page . '/' . $pages . ' 页</span>'
          . '</form>';

    if (!$slice) {
        $out .= '<div class="empty">没有匹配的网址，试试调整筛选条件。</div>';
    } else {
        $out .= '<div class="table-wrap"><table><thead><tr>'
              . '<th class="w-cat">栏目</th><th class="w-ico">图标</th><th class="w-name">名称</th>'
              . '<th>网址</th><th>描述</th><th class="w-tags">标签</th><th class="w-ops">操作</th>'
              . '</tr></thead><tbody>';
        $labels = remark_options();
        $back = array('tab' => 'sites', 'q' => $q, 'cat' => $cat, 'page' => $page);
        foreach ($slice as $entry) {
            $r = $entry['r'];
            $tags = '';
            foreach ($r['remark'] as $k) {
                $tags .= '<span class="tag">' . h(isset($labels[$k]) ? $labels[$k] : $k) . '</span>';
            }
            if ($tags === '') $tags = '<span class="muted">—</span>';
            $editUrl = nav_url(array_merge($back, array('edit' => $r['id'])));
            $out .= '<tr>'
                  . '<td><span class="pill">' . h($r['category']) . '</span></td>'
                  . '<td><img class="site-logo" src="' . h(admin_icon_url($r['logo'])) . '" alt="" width="32" height="32" loading="lazy"></td>'
                  . '<td><strong>' . h($r['name']) . '</strong></td>'
                  . '<td><a class="cell-url" href="' . h($r['url']) . '" target="_blank" rel="noopener noreferrer">' . h($r['url']) . '</a></td>'
                  . '<td><div class="cell-desc muted">' . h($r['desc']) . '</div></td>'
                  . '<td>' . $tags . '</td>'
                  . '<td class="actions">'
                  . '<a class="btn btn-ghost btn-xs" href="' . h($editUrl) . '">编辑</a> '
                  . '<form class="inline-form" method="post">' . csrf_field()
                  . '<input type="hidden" name="action" value="move_site"><input type="hidden" name="id" value="' . h($r['id']) . '">'
                  . '<input type="hidden" name="dir" value="up"><button class="btn btn-ghost btn-xs" type="submit" title="上移">↑</button></form>'
                  . '<form class="inline-form" method="post">' . csrf_field()
                  . '<input type="hidden" name="action" value="move_site"><input type="hidden" name="id" value="' . h($r['id']) . '">'
                  . '<input type="hidden" name="dir" value="down"><button class="btn btn-ghost btn-xs" type="submit" title="下移">↓</button></form>'
                  . '<form class="inline-form" method="post" data-confirm="' . h('确认删除「' . $r['name'] . '」？此操作不可撤销（可用快照恢复）。') . '">'
                  . csrf_field() . '<input type="hidden" name="action" value="delete_site">'
                  . '<input type="hidden" name="id" value="' . h($r['id']) . '">'
                  . '<label class="check-mini"><input type="checkbox" name="del_icon" value="1" checked>删图标</label>'
                  . '<button class="btn btn-danger btn-xs" type="submit">删除</button></form>'
                  . '</td></tr>';
        }
        $out .= '</tbody></table></div>';

        if ($pages > 1) {
            $out .= '<div class="pager"><span class="info">每页 ' . PER_PAGE . ' 条</span>';
            $from = max(1, $page - 2);
            $to = min($pages, $from + 4);
            for ($i = $from; $i <= $to; $i++) {
                $params = array_merge($back, array('page' => $i));
                $out .= $i === $page
                    ? '<span class="cur">' . $i . '</span>'
                    : '<a href="' . h(nav_url($params)) . '">' . $i . '</a>';
            }
            $out .= '</div>';
        }
    }
    $out .= '</div></div>';
    return $out;
}

/* ------------------------- 栏目管理 ------------------------- */

function categories_tab_html($cfg, $rows, $cats) {
    $counts = array();
    foreach ($rows as $r) $counts[$r['category']] = isset($counts[$r['category']]) ? $counts[$r['category']] + 1 : 1;

    $out = '<div class="card"><div class="card-head"><h2>新增栏目</h2><span class="sub">栏目顺序即静态页左侧导航顺序</span></div>'
          . '<div class="card-body"><form class="inline-form gap-lg" method="post">'
          . csrf_field() . '<input type="hidden" name="action" value="save_category">'
          . '<input type="hidden" name="cat_id" value="">'
          . '<input type="text" name="name" placeholder="栏目名称" maxlength="30" required>'
          . '<button class="btn btn-primary btn-sm" type="submit">新增栏目</button>'
          . '<span class="muted">不能包含 &lt; &gt; " \' / \\ 及「全部」等保留词</span>'
          . '</form></div></div>';

    $out .= '<div class="card"><div class="card-head"><h2>栏目列表</h2><span class="sub">重命名会同步更新该栏目下所有网址</span></div>'
          . '<div class="card-body"><div class="table-wrap"><table><thead><tr>'
          . '<th class="w-ico">#</th><th>栏目名称（可直接修改）</th><th class="w-cat">网址数</th><th class="w-ops">操作</th>'
          . '</tr></thead><tbody>';
    $n = count($cats);
    foreach ($cats as $i => $c) {
        $cnt = isset($counts[$c]) ? $counts[$c] : 0;
        $moveOpts = '<option value="">迁移到…</option>';
        foreach ($cats as $other) {
            if ($other !== $c) $moveOpts .= '<option value="' . h($other) . '">' . h($other) . '</option>';
        }
        $moveOpts .= '<option value="__uncategorized__">未分类（自动新建）</option>';
        $out .= '<tr><td class="muted">' . ($i + 1) . '</td>'
              . '<td><form class="inline-form" method="post">' . csrf_field()
              . '<input type="hidden" name="action" value="save_category">'
              . '<input type="hidden" name="cat_id" value="' . h($c) . '">'
              . '<input type="text" name="name" value="' . h($c) . '" maxlength="30" required>'
              . '<button class="btn btn-ghost btn-xs" type="submit">保存</button></form></td>'
              . '<td><span class="pill">' . $cnt . ' 条</span></td>'
              . '<td class="actions">'
              . '<form class="inline-form" method="post">' . csrf_field()
              . '<input type="hidden" name="action" value="move_category"><input type="hidden" name="cat_id" value="' . h($c) . '">'
              . '<input type="hidden" name="dir" value="up"><button class="btn btn-ghost btn-xs" type="submit"' . ($i === 0 ? ' disabled' : '') . ' title="上移">↑</button></form>'
              . '<form class="inline-form" method="post">' . csrf_field()
              . '<input type="hidden" name="action" value="move_category"><input type="hidden" name="cat_id" value="' . h($c) . '">'
              . '<input type="hidden" name="dir" value="down"><button class="btn btn-ghost btn-xs" type="submit"' . ($i === $n - 1 ? ' disabled' : '') . ' title="下移">↓</button></form>'
              . '<form class="inline-form" method="post" data-confirm="' . h('确认删除栏目「' . $c . '」？' . ($cnt > 0 ? '其下 ' . $cnt . ' 条网址将迁移到所选栏目。' : '')) . '">'
              . csrf_field() . '<input type="hidden" name="action" value="delete_category">'
              . '<input type="hidden" name="cat_id" value="' . h($c) . '">'
              . ($cnt > 0 ? '<select name="move_to" required>' . $moveOpts . '</select>' : '')
              . '<button class="btn btn-danger btn-xs" type="submit">删除</button></form>'
              . '</td></tr>';
    }
    $out .= '</tbody></table></div></div></div>';
    return $out;
}

/* ------------------------- 静态页面 ------------------------- */

function generate_tab_html($cfg, $rows, $cats) {
    $file = output_filename($cfg);
    $path = PUBLIC_ROOT . '/' . $file;
    $exists = is_file($path);
    $size = $exists ? @filesize($path) : 0;
    $mtime = $exists ? date('Y-m-d H:i:s', @filemtime($path)) : '尚未生成';
    $tplOk = is_file(TEMPLATE_FILE) && strpos((string)@file_get_contents(TEMPLATE_FILE), '__NAV_DATA_JSON__') !== false;
    $updated = setting_get('data_updated', '—');

    $kv = '';
    $items = array(
        '模板文件'   => $tplOk ? '<span class="badge badge-ok">admin/template.html 正常</span>' : '<span class="badge badge-bad">模板缺失 / 占位符损坏</span>',
        '输出文件'   => h($file),
        '上次生成'   => h($mtime),
        '页面体积'   => $size ? number_format($size / 1024, 1) . ' KB' : '—',
        '网址数量'   => count($rows) . ' 条',
        '栏目数量'   => count($cats) . ' 个',
        '数据更新'   => h($updated),
        '自动生成'   => !empty($cfg['auto_generate']) ? '<span class="badge badge-ok">已开启</span>' : '<span class="badge badge-warn">已关闭</span>'
    );
    foreach ($items as $k => $v) $kv .= '<div><b>' . h($k) . '</b><span>' . $v . '</span></div>';

    $out = '<div class="card"><div class="card-head"><h2>生成静态导航页</h2>'
          . '<span class="sub">把数据内嵌进 HTML，前台零请求、可离线打开</span></div>'
          . '<div class="card-body"><div class="kv">' . $kv . '</div>'
          . '<div class="form-actions">'
          . '<form method="post">' . csrf_field() . '<input type="hidden" name="action" value="generate">'
          . '<button class="btn btn-primary" type="submit">立即生成静态页面</button></form>'
          . ($exists ? '<a class="btn btn-ghost" href="' . h(public_asset_url($file)) . '" target="_blank" rel="noopener noreferrer">查看静态页面</a>' : '')
          . '</div>'
          . '<p class="hint">输出位置为 public/，生成时会先备份旧页面到 admin/backup/；浏览器可能缓存旧版，查看时可按 Ctrl+F5 强制刷新。</p>'
          . '</div></div>';

    $out .= '<div class="card"><div class="card-head"><h2>静态页内置优化</h2></div><div class="card-body">'
          . '<div class="kv">'
          . '<div><b>零运行期请求</b><span>数据由 SQLite 生成并内嵌进 HTML，前台不请求任何数据文件</span></div>'
          . '<div><b>本地字体</b><span>Font Awesome 本地化并预加载 woff2，去掉第三方 CDN</span></div>'
          . '<div><b>严格 CSP</b><span>对内嵌脚本 / 样式计算 sha256 哈希，禁止外部脚本与内联事件</span></div>'
          . '<div><b>输出转义</b><span>名称、描述、URL、图标路径全部白名单校验后转义</span></div>'
          . '<div><b>渲染性能</b><span>事件委托 + 搜索防抖 + 数组拼接 + 图标懒加载 / 固定尺寸</span></div>'
          . '<div><b>主题记忆</b><span>夜间模式、分类切换、图标说明弹层保持原有交互与样式</span></div>'
          . '</div></div></div>';
    return $out;
}

/* ------------------------- 系统设置 ------------------------- */

function settings_tab_html($cfg, $rows, $cats) {
    $idleOpts = '';
    foreach (array(900 => '15 分钟', 1800 => '30 分钟', 3600 => '1 小时', 7200 => '2 小时', 28800 => '8 小时') as $v => $label) {
        $idleOpts .= '<option value="' . $v . '"' . ((int)$cfg['session_idle'] === $v ? ' selected' : '') . '>' . h($label) . '</option>';
    }
    $out = '<div class="split">';
    $out .= '<div class="card"><div class="card-head"><h2>常规设置</h2></div><div class="card-body">'
          . '<form method="post">' . csrf_field() . '<input type="hidden" name="action" value="save_settings">'
          . '<div class="stack">'
          . '<div class="field"><label>站点标题</label><input type="text" name="site_title" value="' . h($cfg['site_title']) . '" maxlength="60" required></div>'
          . '<div class="field"><label>静态页输出文件名</label><input type="text" name="output_file" value="' . h($cfg['output_file']) . '" maxlength="40" required>'
          . '<span class="hint">仅允许字母、数字、-、_ 与 .html 后缀，始终写在 public/ 目录</span></div>'
          . '<div class="field"><label>会话空闲超时</label><select name="session_idle">' . $idleOpts . '</select></div>'
          . '<label class="check"><input type="checkbox" name="auto_generate" value="1"' . (!empty($cfg['auto_generate']) ? ' checked' : '') . '>每次增删改后自动生成静态页面</label>'
          . '</div><div class="form-actions"><button class="btn btn-primary" type="submit">保存设置</button></div>'
          . '</form></div></div>';

    $out .= '<div class="card"><div class="card-head"><h2>修改密码</h2>'
          . '<span class="sub">' . (!empty($cfg['default_password']) ? '<span class="badge badge-warn">仍是初始密码</span>' : '<span class="badge badge-ok">已自定义</span>') . '</span></div>'
          . '<div class="card-body"><form method="post">' . csrf_field()
          . '<input type="hidden" name="action" value="change_password">'
          . '<div class="stack">'
          . '<div class="field"><label>当前密码</label><input type="password" name="current_password" required autocomplete="current-password"></div>'
          . '<div class="field"><label>新密码（至少 8 位）</label><input type="password" name="new_password" required autocomplete="new-password"></div>'
          . '<div class="field"><label>确认新密码</label><input type="password" name="new_password2" required autocomplete="new-password"></div>'
          . '</div><div class="form-actions"><button class="btn btn-primary" type="submit">更新密码</button></div>'
          . '</form></div></div>';
    $out .= '</div>';

    /* 备份与恢复 */
    $list = snapshot_list();
    $rowsHtml = '';
    if (!$list) $rowsHtml = '<div class="empty">暂无快照。每次修改数据前系统都会自动创建一份。</div>';
    foreach ($list as $s) {
        $rowsHtml .= '<div class="file-row"><span class="name">' . h($s['file']) . '</span>'
                   . '<span class="muted">' . h($s['time']) . '</span>'
                   . '<span class="pill">' . (int)$s['sites'] . ' 条</span>'
                   . '<span class="grow"></span>'
                   . '<form class="inline-form" method="post" data-confirm="' . h('确认用该快照覆盖当前数据？当前数据会先自动备份。') . '">'
                   . csrf_field() . '<input type="hidden" name="action" value="restore">'
                   . '<input type="hidden" name="file" value="' . h($s['file']) . '">'
                   . '<button class="btn btn-danger btn-xs" type="submit">恢复</button></form></div>';
    }
    $out .= '<div class="card"><div class="card-head"><h2>数据备份与恢复</h2><span class="sub">快照为 SQLite 数据库副本，保存在 admin/backup/，Web 不可直接访问</span></div>'
          . '<div class="card-body"><div class="form-actions tight">'
          . '<form method="post">' . csrf_field() . '<input type="hidden" name="action" value="snapshot">'
          . '<button class="btn btn-ghost btn-sm" type="submit">立即创建快照</button></form>'
          . '<form method="post">' . csrf_field() . '<input type="hidden" name="action" value="export_data">'
          . '<button class="btn btn-ghost btn-sm" type="submit">导出 SQLite 数据库</button></form>'
          . '</div><div class="file-list">' . $rowsHtml . '</div></div></div>';

    /* 系统信息 */
    $checks = array(
        'pdo_sqlite 扩展'      => extension_loaded('pdo_sqlite'),
        '数据库文件可写'        => is_writable_safe(DB_FILE),
        '数据库目录可写'        => is_writable_safe(DB_DIR),
        'public/ 可写（静态页）'=> is_writable_safe(PUBLIC_ROOT),
        'public/ico/ 可写'     => is_writable_safe(UPLOAD_DIR),
        'admin/backup/ 可写'   => is_writable_safe(BACKUP_DIR),
        '模板文件存在'          => is_file(TEMPLATE_FILE),
        'cURL 扩展'             => function_exists('curl_init')
    );
    $info = '';
    foreach ($checks as $k => $v) {
        $info .= '<div><b>' . h($k) . '</b><span>' . ($v ? '<span class="badge badge-ok">正常</span>' : '<span class="badge badge-bad">异常</span>') . '</span></div>';
    }
    $info .= '<div><b>PHP 版本</b><span>' . h(PHP_VERSION) . '</span></div>';
    $info .= '<div><b>当前网址 / 栏目</b><span>' . count($rows) . ' 条 / ' . count($cats) . ' 个</span></div>';
    $info .= '<div><b>服务器时间</b><span>' . h(date('Y-m-d H:i:s')) . '</span></div>';
    $out .= '<div class="card"><div class="card-head"><h2>系统信息</h2></div>'
          . '<div class="card-body"><div class="kv">' . $info . '</div>'
          . '<p class="hint">提示：网址、栏目、设置、密码哈希与登录限流全部存于 admin/data/nav.sqlite；数据库、快照和后台程序位于 Web 根目录之外，并由 .htaccess 拒绝直接访问；后台与静态页均启用严格 CSP。</p>'
          . '</div></div>';
    return $out;
}

function is_writable_safe($path) {
    if (is_dir($path)) return is_writable($path);
    if (is_file($path)) return is_writable($path);
    return is_writable(dirname($path));
}

/* ==================================================================
 * 九、入口
 * ================================================================== */

ensure_dirs();
$cfg = config_load();
start_session($cfg === null ? 1800 : $cfg['session_idle']);
$logged = ($cfg !== null) && is_logged_in($cfg['session_idle']);

if (is_post()) {
    handle_post(post('action'), $cfg, $logged);
}

if ($cfg === null) {
    render_install();
    exit;
}
if (!$logged) {
    render_login($cfg);
    exit;
}

$tab = getq('tab', 'sites');
if (!in_array($tab, array('sites', 'categories', 'generate', 'settings'), true)) $tab = 'sites';
$G_LOAD_ERROR = '';
list($allRows, $allCats) = load_all();

$body = '';
if (!empty($cfg['default_password'])) {
    $body .= '<div class="notice notice-warn">当前仍在使用初始密码，请立即到「系统设置 → 修改密码」更换，避免后台被未授权访问。</div>';
}
if ($G_LOAD_ERROR !== '') $body .= '<div class="flash flash-error">' . h($G_LOAD_ERROR) . '</div>';

switch ($tab) {
    case 'categories': $body .= categories_tab_html($cfg, $allRows, $allCats); break;
    case 'generate':   $body .= generate_tab_html($cfg, $allRows, $allCats); break;
    case 'settings':   $body .= settings_tab_html($cfg, $allRows, $allCats); break;
    default:           $body .= sites_tab_html($cfg, $allRows, $allCats); break;
}

render_shell($tab === 'sites' ? '网址管理' : '网址导航后台', $body, $cfg, chrome_html($cfg, $tab));

<?php
// 配置
define('ADMIN_PASSWORD', 'tianliang'); // 设置管理员密码
define('JSON_FILE', 'websites.json');
define('UPLOAD_DIR', 'ico/');
define('ALLOWED_IMAGE_TYPES', ['jpg', 'jpeg', 'png', 'gif', 'ico', 'svg']);

// 初始化
ini_set('session.gc_maxlifetime', 1800);
session_start();
$response = [];

// 确保上传目录存在
if (!is_dir(UPLOAD_DIR)) {
    mkdir(UPLOAD_DIR, 0755, true);
}

// 处理登录
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['password'])) {
    if ($_POST['password'] === ADMIN_PASSWORD) {
        $_SESSION['is_logged_in'] = true;
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    } else {
        $response['error'] = '密码错误';
    }
}

// 检查是否已登录
if (!isset($_SESSION['is_logged_in']) || !$_SESSION['is_logged_in']) {
    ?>
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>登录 - JSON数据管理</title>
        <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 0; display: flex; justify-content: center; align-items: center; min-height: 100vh; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
            .login-container { background: rgba(255,255,255,0.95); padding: 2.5rem; border-radius: 12px; box-shadow: 0 10px 40px rgba(0,0,0,0.2); width: 350px; backdrop-filter: blur(5px); }
            .login-container h1 { margin: 0 0 1.5rem 0; text-align: center; color: #333; font-weight: 300; }
            .login-form { display: flex; flex-direction: column; gap: 1.2rem; }
            .login-form input[type="password"] { padding: 0.8rem 1rem; border: 2px solid #e0e0e0; border-radius: 8px; font-size: 1rem; transition: border-color 0.3s; }
            .login-form input[type="password"]:focus { border-color: #667eea; outline: none; }
            .login-form button { padding: 0.8rem; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; border-radius: 8px; font-size: 1rem; font-weight: 500; cursor: pointer; transition: transform 0.2s; }
            .login-form button:hover { transform: translateY(-2px); box-shadow: 0 5px 15px rgba(102,126,234,0.4); }
            .error { color: #e74c3c; text-align: center; margin-bottom: 1rem; font-size: 0.9rem; }
        </style>
    </head>
    <body>
        <div class="login-container">
            <h1>🔐 管理登录</h1>
            <?php if (isset($response['error'])): ?>
                <div class="error"><?= htmlspecialchars($response['error']) ?></div>
            <?php endif; ?>
            <form class="login-form" method="post">
                <input type="password" name="password" placeholder="请输入密码" required>
                <button type="submit">登录</button>
            </form>
        </div>
    </body>
    </html>
    <?php
    exit;
}

$data = readJsonData();
$categories = getCategoryList($data);

// 处理请求
handleRequest();

// 读取JSON数据
function readJsonData() {
    if (file_exists(JSON_FILE)) {
        $jsonData = file_get_contents(JSON_FILE);
        return json_decode($jsonData, true) ?: [];
    }
    return [];
}

// 写入JSON数据
function writeJsonData($data) {
    $jsonData = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    return file_put_contents(JSON_FILE, $jsonData) !== false;
}

// 获取分类列表
function getCategoryList($data) {
    $categories = array_column($data, 'category');
    return array_unique($categories);
}

// 处理文件上传
function handleFileUpload() {
    if (!isset($_FILES['image'])) {
        return ['error' => '未接收到文件'];
    }

    $uploadFile = UPLOAD_DIR . basename($_FILES['image']['name']);
    $imageFileType = strtolower(pathinfo($uploadFile, PATHINFO_EXTENSION));

    if (!in_array($imageFileType, ALLOWED_IMAGE_TYPES)) {
        return ['error' => '只允许上传图片'];
    }

    if (file_exists($uploadFile)) {
        return ['error' => '文件已存在'];
    }

    if (move_uploaded_file($_FILES['image']['tmp_name'], $uploadFile)) {
        return [
            'success' => true,
            'image_name' => basename($_FILES['image']['name']),
            'image_path' => $uploadFile
        ];
    }

    return ['error' => '文件上传失败'];
}

// 下载并保存网站图标
function downloadFavicon($url) {
    // 解析域名
    $parsed = parse_url($url);
    if (empty($parsed['host'])) {
        return ['error' => '无效的URL'];
    }
    $domain = $parsed['host'];
    
    // 尝试获取favicon.ico
    $faviconUrl = $parsed['scheme'] . '://' . $domain . '/favicon.ico';
    
    // 初始化cURL
    $ch = curl_init($faviconUrl);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36');
    
    $imageData = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $contentType = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
    curl_close($ch);
    
    if ($httpCode !== 200 || empty($imageData)) {
        return ['error' => '无法获取图标，请手动上传'];
    }
    
    // 确定文件扩展名
    $ext = 'ico';
    if (strpos($contentType, 'image/png') !== false) {
        $ext = 'png';
    } elseif (strpos($contentType, 'image/jpeg') !== false) {
        $ext = 'jpg';
    } elseif (strpos($contentType, 'image/gif') !== false) {
        $ext = 'gif';
    } elseif (strpos($contentType, 'image/svg+xml') !== false) {
        $ext = 'svg';
    }
    
    // 生成文件名：domain.扩展名
    $filename = $domain . '.' . $ext;
    $filepath = UPLOAD_DIR . $filename;
    
    // 避免重名，如果已存在则添加数字后缀
    $counter = 1;
    $originalFilename = $filename;
    while (file_exists($filepath)) {
        $filename = pathinfo($originalFilename, PATHINFO_FILENAME) . '_' . $counter . '.' . $ext;
        $filepath = UPLOAD_DIR . $filename;
        $counter++;
    }
    
    if (file_put_contents($filepath, $imageData)) {
        return [
            'success' => true,
            'path' => $filepath,
            'filename' => $filename
        ];
    } else {
        return ['error' => '保存图标失败，请检查目录权限'];
    }
}

// 处理AJAX请求（自动获取图标）
function handleAjaxRequest() {
    if (isset($_GET['action']) && $_GET['action'] === 'get_ico' && isset($_GET['url'])) {
        header('Content-Type: application/json');
        $url = trim($_GET['url']);
        if (empty($url)) {
            echo json_encode(['error' => 'URL不能为空']);
            exit;
        }
        // 添加协议前缀（如果没有）
        if (!preg_match('/^https?:\/\//i', $url)) {
            $url = 'http://' . $url;
        }
        $result = downloadFavicon($url);
        echo json_encode($result);
        exit;
    }
}

// 调用AJAX处理
handleAjaxRequest();

// 处理表单提交
function handleFormSubmission(&$data) {
    $item = [
        'category' => $_POST['category'],
        'name' => $_POST['name'],
        'url' => $_POST['url'],
        'logo' => $_POST['logo'],
        'desc' => $_POST['desc'],
        'remark' => $_POST['remark'] ?? []
    ];

    if (isset($_POST['submit_add'])) {
        $lastIndex = -1;
        foreach ($data as $index => $existingItem) {
            if ($existingItem['category'] === $_POST['category']) {
                $lastIndex = $index;
            }
        }
        $lastIndex !== -1 ? array_splice($data, $lastIndex + 1, 0, [$item]) : $data[] = $item;
        return "添加成功";
    }

    if (isset($_POST['submit_edit']) && isset($_GET['index'])) {
        $index = intval($_GET['index']);
        if ($index >= 0 && $index < count($data)) {
            $data[$index] = $item;
            return "编辑成功";
        }
    }

    return false;
}

// 处理删除操作
function handleDelete(&$data) {
    if (isset($_GET['action']) && $_GET['action'] == 'delete' && isset($_GET['index'])) {
        $index = intval($_GET['index']);
        if ($index >= 0 && $index < count($data)) {
            array_splice($data, $index, 1);
            return "删除成功";
        }
    }
    return false;
}

// 主请求处理函数
function handleRequest() {
    global $data, $response;

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['image'])) {
        $response = handleFileUpload();
    } elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if ($message = handleFormSubmission($data)) {
            if (writeJsonData($data)) {
                header("Location: ?message=" . urlencode($message));
                exit;
            }
            $response['error'] = "操作失败，请检查文件权限";
        }
    } elseif ($message = handleDelete($data)) {
        if (writeJsonData($data)) {
            header("Location: ?message=" . urlencode($message));
            exit;
        }
        $response['error'] = "删除失败，请检查文件权限";
    }
}

// 显示消息
function displayMessage() {
    if (isset($_GET['message'])) {
        echo "<div class='message success'>" . htmlspecialchars(urldecode($_GET['message'])) . "</div>";
    }
    if (isset($GLOBALS['response']['error'])) {
        echo "<div class='message error'>" . htmlspecialchars($GLOBALS['response']['error']) . "</div>";
    }
}

// 显示表单
function displayForm($categories, $editItem = null) {
    $isEditMode = $editItem !== null;
    $options = [
        "windows" => "微软系统适用",
        "mac" => "苹果系统适用",
        "linux" => "linux系统适用",
        "android" => "安卓系统适用",
        "fufei" => "需要付费使用",
        "kexue" => "大陆地区无法访问",
        "heart" => "推荐网站",
        "github" => "github资源"
    ];
    ?>
    <div class="form-container <?= $isEditMode ? 'edit-mode' : '' ?>">
        <h2><?= $isEditMode ? '✏️ 编辑条目' : '➕ 添加新条目' ?></h2>
        <form action="" method="post" enctype="multipart/form-data" id="mainForm">
            <input type="hidden" name="<?= $isEditMode ? 'submit_edit' : 'submit_add' ?>">
            
            <div class="form-group">
                <label>分类：</label>
                <select name="category" required>
                    <option value="">-- 选择分类 --</option>
                    <?php foreach ($categories as $cat) : ?>
                        <option value="<?= htmlspecialchars($cat) ?>" <?= ($isEditMode && $editItem['category'] == $cat) ? 'selected' : '' ?>>
                            <?= htmlspecialchars($cat) ?>
                        </option>
                    <?php endforeach; ?>
                    <option value="new">➕ 新建分类...</option>
                </select>
                <input type="text" name="new_category" placeholder="输入新分类" style="display:none; margin-top:5px;" />
            </div>

            <div class="form-group">
                <label>名称：</label>
                <input type="text" name="name" value="<?= $isEditMode ? htmlspecialchars($editItem['name']) : '' ?>" required>
            </div>

            <div class="form-group">
                <label>URL：</label>
                <div style="display: flex; gap: 5px;">
                    <input type="url" name="url" id="site-url" value="<?= $isEditMode ? htmlspecialchars($editItem['url']) : '' ?>" required placeholder="https://example.com" style="flex:1;">
                    <button type="button" id="fetch-icon-btn" class="btn-secondary" style="white-space: nowrap;">获取图标</button>
                </div>
                <small class="hint">输入URL后点击按钮获取网站图标，或等待自动获取</small>
            </div>

            <div class="form-group">
                <label>Logo：</label>
                <div style="display: flex; gap: 10px;">
                    <input type="text" name="logo" id="logo-input" value="<?= $isEditMode ? htmlspecialchars($editItem['logo']) : '' ?>" required style="flex:1;" placeholder="图标路径或URL">
                    <span id="logo-preview" style="display: <?= ($isEditMode && !empty($editItem['logo'])) ? 'inline-block' : 'none' ?>;">
                        <img src="<?= $isEditMode ? htmlspecialchars($editItem['logo']) : '' ?>" alt="logo预览" style="max-width:32px; max-height:32px;">
                    </span>
                </div>
            </div>

            <div class="form-group">
                <label>描述：</label>
                <textarea name="desc" required rows="3"><?= $isEditMode ? htmlspecialchars($editItem['desc']) : '' ?></textarea>
            </div>

            <div class="form-group checkboxes">
                <label>标签：</label>
                <div class="checkbox-group">
                    <?php foreach ($options as $key => $value): ?>
                        <label class="checkbox-item">
                            <input type="checkbox" name="remark[]" value="<?= $key ?>" 
                                <?= ($isEditMode && in_array($key, $editItem['remark'])) ? 'checked' : '' ?>>
                            <?= htmlspecialchars($value) ?>
                        </label>
                    <?php endforeach; ?>
                </div>
            </div>

            <div class="form-actions">
                <button type="submit" class="btn-primary"><?= $isEditMode ? '保存修改' : '添加条目' ?></button>
                <?php if ($isEditMode): ?>
                    <a href="?" class="btn-secondary">取消</a>
                <?php endif; ?>
            </div>
        </form>
    </div>

    <script>
        // 处理新建分类
        document.querySelector('select[name="category"]').addEventListener('change', function(e) {
            const newCatInput = document.querySelector('input[name="new_category"]');
            if (this.value === 'new') {
                newCatInput.style.display = 'block';
                newCatInput.required = true;
                newCatInput.focus();
            } else {
                newCatInput.style.display = 'none';
                newCatInput.required = false;
            }
        });

        // 获取图标功能
        const urlInput = document.getElementById('site-url');
        const logoInput = document.getElementById('logo-input');
        const logoPreview = document.getElementById('logo-preview');
        const fetchBtn = document.getElementById('fetch-icon-btn');
        let timeoutId;

        // 定义获取图标的函数
        function fetchIcon(url) {
            if (!url) {
                alert('请输入URL');
                return;
            }

            // 禁用按钮，显示加载状态
            fetchBtn.disabled = true;
            fetchBtn.textContent = '获取中...';

            fetch(`?action=get_ico&url=${encodeURIComponent(url)}`)
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        logoInput.value = data.path;
                        // 更新预览
                        let previewImg = logoPreview.querySelector('img');
                        if (!previewImg) {
                            previewImg = document.createElement('img');
                            logoPreview.appendChild(previewImg);
                        }
                        previewImg.src = data.path + '?t=' + Date.now(); // 防止缓存
                        previewImg.alt = 'logo预览';
                        previewImg.style.maxWidth = '32px';
                        previewImg.style.maxHeight = '32px';
                        logoPreview.style.display = 'inline-block';
                    } else {
                        alert('获取图标失败：' + (data.error || '未知错误'));
                    }
                })
                .catch(err => {
                    console.error('请求失败', err);
                    alert('网络错误，请稍后重试');
                })
                .finally(() => {
                    // 恢复按钮
                    fetchBtn.disabled = false;
                    fetchBtn.textContent = '获取图标';
                });
        }

        // 按钮点击事件
        fetchBtn.addEventListener('click', function() {
            const url = urlInput.value.trim();
            fetchIcon(url);
        });

        // 输入框失去焦点自动获取（带防抖）
        urlInput.addEventListener('blur', function() {
            const url = this.value.trim();
            if (!url) return;

            // 清除之前的延时
            if (timeoutId) clearTimeout(timeoutId);
            
            // 延时发送请求，避免频繁请求
            timeoutId = setTimeout(() => {
                fetchIcon(url);
            }, 500);
        });

        // 当logo输入框变化时，更新预览
        logoInput.addEventListener('input', function() {
            const val = this.value.trim();
            if (val) {
                let previewImg = logoPreview.querySelector('img');
                if (!previewImg) {
                    previewImg = document.createElement('img');
                    logoPreview.appendChild(previewImg);
                }
                previewImg.src = val + '?t=' + Date.now();
                logoPreview.style.display = 'inline-block';
            } else {
                logoPreview.style.display = 'none';
            }
        });

        // 如果是编辑模式，初始化预览
        <?php if ($isEditMode && !empty($editItem['logo'])): ?>
        window.addEventListener('load', function() {
            logoInput.dispatchEvent(new Event('input'));
        });
        <?php endif; ?>
    </script>
    <?php
}
?>

<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>📋 JSON数据管理</title>
    <style>
        * { box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Roboto, system-ui, sans-serif;
            margin: 0;
            background: #f5f7fa;
            color: #2c3e50;
            line-height: 1.6;
        }
        .container {
            max-width: 1400px;
            margin: 20px auto;
            background: white;
            padding: 30px;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.08);
        }
        h1 {
            margin-top: 0;
            font-weight: 400;
            font-size: 2.2rem;
            color: #34495e;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
            display: inline-block;
        }
        .message {
            padding: 15px 20px;
            border-radius: 12px;
            margin-bottom: 25px;
            font-weight: 500;
            animation: slideDown 0.3s ease;
        }
        .message.success {
            background: #d4edda;
            color: #155724;
            border-left: 5px solid #28a745;
        }
        .message.error {
            background: #f8d7da;
            color: #721c24;
            border-left: 5px solid #dc3545;
        }
        @keyframes slideDown {
            from { opacity: 0; transform: translateY(-10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        /* 表单区域 */
        .form-container {
            background: #f9f9fc;
            border-radius: 16px;
            padding: 25px;
            margin: 20px 0 30px;
            border: 1px solid #e9ecef;
            transition: box-shadow 0.3s;
        }
        .form-container:hover {
            box-shadow: 0 5px 15px rgba(0,0,0,0.05);
        }
        .form-group {
            margin-bottom: 20px;
        }
        .form-group label {
            display: block;
            font-weight: 600;
            margin-bottom: 6px;
            color: #495057;
        }
        .form-group input[type="text"],
        .form-group input[type="url"],
        .form-group select,
        .form-group textarea {
            width: 100%;
            padding: 12px 15px;
            border: 2px solid #dee2e6;
            border-radius: 10px;
            font-size: 1rem;
            transition: border-color 0.2s, box-shadow 0.2s;
            background: white;
        }
        .form-group input:focus,
        .form-group select:focus,
        .form-group textarea:focus {
            border-color: #667eea;
            outline: none;
            box-shadow: 0 0 0 3px rgba(102,126,234,0.2);
        }
        .hint {
            display: block;
            color: #6c757d;
            font-size: 0.85rem;
            margin-top: 4px;
        }
        .checkbox-group {
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            background: white;
            padding: 15px;
            border-radius: 10px;
            border: 1px solid #e9ecef;
        }
        .checkbox-item {
            display: flex;
            align-items: center;
            gap: 5px;
            cursor: pointer;
            user-select: none;
        }
        .checkbox-item input[type="checkbox"] {
            width: 18px;
            height: 18px;
            cursor: pointer;
        }
        .form-actions {
            display: flex;
            gap: 15px;
            margin-top: 25px;
        }
        .btn-primary, .btn-secondary {
            padding: 12px 30px;
            border: none;
            border-radius: 10px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            text-decoration: none;
            display: inline-block;
        }
        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            box-shadow: 0 4px 10px rgba(102,126,234,0.3);
        }
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(102,126,234,0.4);
        }
        .btn-secondary {
            background: #e9ecef;
            color: #495057;
            border: 1px solid #ced4da;
        }
        .btn-secondary:hover {
            background: #dee2e6;
        }

        /* 表格 */
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 30px;
            background: white;
            border-radius: 16px;
            overflow: hidden;
            box-shadow: 0 5px 15px rgba(0,0,0,0.05);
        }
        th {
            background: #f8f9fa;
            color: #2c3e50;
            font-weight: 600;
            padding: 4px 6px;
            border-bottom: 2px solid #dee2e6;
        }
        td {
            padding: 8px;
            border-bottom: 1px solid #e9ecef;
            vertical-align: middle;
        }
        tr:last-child td {
            border-bottom: none;
        }
        tr:hover td {
            background: #f8f9fc;
        }
        td img {
            width: 32px;
            height: 32px;
            object-fit: contain;
            border-radius: 6px;
            background: #f1f3f5;
            padding: 2px;
        }
        .action-links a {
            color: #667eea;
            text-decoration: none;
            margin: 0 5px;
            font-weight: 500;
            transition: color 0.2s;
        }
        .action-links a:hover {
            color: #764ba2;
            text-decoration: underline;
        }
        .action-links a.delete {
            color: #e74c3c;
        }
        .action-links a.delete:hover {
            color: #c0392b;
        }

        /* 上传区域 */
        .upload-section {
            background: #f1f8fe;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 20px;
            flex-wrap: wrap;
        }
        .upload-section label {
            font-weight: 600;
            color: #2c3e50;
        }
        .upload-section input[type="file"] {
            flex: 1;
            padding: 8px;
            background: white;
            border: 1px dashed #667eea;
            border-radius: 8px;
        }
        .upload-section button {
            background: #6c757d;
            color: white;
            border: none;
            padding: 10px 25px;
            border-radius: 8px;
            cursor: pointer;
            transition: background 0.2s;
        }
        .upload-section button:hover {
            background: #5a6268;
        }
        .upload-result {
            margin-top: 10px;
            padding: 10px;
            border-radius: 8px;
        }
        .upload-result.success {
            background: #d4edda;
            color: #155724;
        }
        .upload-result.error {
            background: #f8d7da;
            color: #721c24;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>📁 网站数据管理</h1>
        <?php displayMessage(); ?>
        
        <!-- 上传区域（原有功能） -->
        <div class="upload-section">
            <label for="image">📤 手动上传图标：</label>
            <input type="file" name="image" id="image" accept="image/*" form="uploadForm">
            <button type="submit" form="uploadForm">上传</button>
            <?php if (!empty($response) && isset($response['image_name'])): ?>
                <div class="upload-result success">
                    上传成功！图片：<?= htmlspecialchars($response['image_name']) ?>
                </div>
            <?php elseif (isset($response['error'])): ?>
                <div class="upload-result error">
                    <?= htmlspecialchars($response['error']) ?>
                </div>
            <?php endif; ?>
        </div>
        <form id="uploadForm" action="" method="post" enctype="multipart/form-data" style="display:none;"></form>

        <!-- 添加/编辑表单 -->
        <?php if (!isset($_GET['action']) || $_GET['action'] != 'edit'): ?>
            <?php displayForm($categories); ?>
        <?php endif; ?>

        <?php if (isset($_GET['action']) && $_GET['action'] == 'edit' && isset($_GET['index'])): ?>
            <?php
            $index = intval($_GET['index']);
            if ($index >= 0 && $index < count($data)) {
                $editItem = $data[$index];
                if (!isset($editItem['remark'])) {
                    $editItem['remark'] = [];
                }
                displayForm($categories, $editItem);
            }
            ?>
        <?php endif; ?>

        <!-- 数据表格 -->
        <table>
            <thead>
                <tr>
                    <th style="width:120px">分类</th>
                    <th style="width:200px">名称</th>
                    <th>URL</th>
                    <th style="width:42px">Logo</th>
                    <th>描述</th>
                    <th style="width:180px">操作</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($data as $index => $item): ?>
                <tr>
                    <td><?= htmlspecialchars($item['category']) ?></td>
                    <td><?= htmlspecialchars($item['name']) ?></td>
                    <td><a href="<?= htmlspecialchars($item['url']) ?>" target="_blank"><?= htmlspecialchars($item['url']) ?></a></td>
                    <td><img src="<?= htmlspecialchars($item['logo']) ?>" alt="logo" loading="lazy"></td>
                    <td><?= htmlspecialchars($item['desc']) ?></td>
                    <td class="action-links">
                        <a href="?action=edit&index=<?= $index ?>">✏️ 编辑</a>
                        <a href="?action=delete&index=<?= $index ?>" class="delete" onclick="return confirm('确认删除该条目？')">🗑️ 删除</a>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</body>
</html>
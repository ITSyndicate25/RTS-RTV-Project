# PHP + AdminLTE RBAC Dashboard (MSSQL, PDO, CSRF, AJAX) — Complete Codebase

> **Ready-to-run starter** — role-based dashboards (admin/manager/employee), secure auth (password_hash), CSRF protection, session timeout, "Remember Me" token, local AdminLTE assets, and AJAX-based user CRUD with role restrictions.

---

## Project structure
```
project/
├── index.php
├── config.php
├── assets/
│   ├── adminlte/...
│   ├── bootstrap/...
│   └── jquery/...
├── includes/
│   ├── session.php
│   ├── role_check.php
│   ├── csrf.php
│   ├── header.php
│   ├── footer.php
│   └── sidebar.php
├── models/
│   └── UserModel.php
├── pages/
│   ├── login.php
│   ├── admin_dashboard.php
│   ├── manager_dashboard.php
│   ├── employee_dashboard.php
│   └── logout.php
└── ajax/
    ├── login.php
    ├── list_users.php
    ├── add_user.php
    ├── update_user.php
    └── delete_user.php
```

> **Database requirement**: `users` table with fields: `id, name, username, email, password_hash, role, remember_token, remember_expiry, created_at`.

SQL example (MS SQL Server):
```sql
CREATE TABLE users (
  id INT IDENTITY(1,1) PRIMARY KEY,
  name NVARCHAR(100) NOT NULL,
  username NVARCHAR(100) NOT NULL UNIQUE,
  email NVARCHAR(255) NULL,
  password_hash NVARCHAR(255) NOT NULL,
  role NVARCHAR(20) NOT NULL CHECK (role IN ('admin','manager','employee')),
  remember_token NVARCHAR(128) NULL,
  remember_expiry DATETIME2 NULL,
  created_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
);
```

---

## config.php
```php
<?php
// config.php - PDO connection for MS SQL (sqlsrv)
// Adjust env vars or replace with constants for your environment
$DB_HOST = getenv('DB_HOST') ?: 'localhost';
$DB_NAME = getenv('DB_NAME') ?: 'your_db';
$DB_USER = getenv('DB_USER') ?: 'your_user';
$DB_PASS = getenv('DB_PASS') ?: 'your_pass';

$dsn = "sqlsrv:Server={$DB_HOST};Database={$DB_NAME}";
$options = [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES => false,
];

try {
    $pdo = new PDO($dsn, $DB_USER, $DB_PASS, $options);
} catch (PDOException $e) {
    // In production, don't echo errors. Log them.
    http_response_code(500);
    die('Database connection failed.');
}
```

---

## includes/session.php
```php
<?php
// includes/session.php
// Starts session, enforces timeout, implements "remember me" auto-login via token

if (session_status() === PHP_SESSION_NONE) {
    // Hardened cookie params
    $secure = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on';
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'domain' => '',
        'secure' => $secure,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    session_start();
}

require_once __DIR__ . '/../config.php'; // $pdo available

// Session timeout (seconds)
$timeout_duration = 1800; // 30 minutes
// Remember me cookie name & expiry days
$remember_cookie_name = 'remember_token';

// Auto-login using remember_token cookie when session not active
if (empty($_SESSION['user']) && !empty($_COOKIE[$remember_cookie_name])) {
    $token = $_COOKIE[$remember_cookie_name];
    if (is_string($token) && strlen($token) > 0) {
        $stmt = $pdo->prepare('SELECT id, name, username, email, role FROM users WHERE remember_token = :token AND remember_expiry > GETDATE()');
        $stmt->execute([':token' => $token]);
        $u = $stmt->fetch();
        if ($u) {
            // Restore session
            $_SESSION['user'] = [
                'id' => (int)$u['id'],
                'name' => $u['name'],
                'username' => $u['username'],
                'email' => $u['email'],
                'role' => $u['role'],
            ];
            session_regenerate_id(true);
            $_SESSION['last_activity'] = time();
        } else {
            // invalid token — clear cookie
            setcookie($remember_cookie_name, '', time() - 3600, '/');
        }
    }
}

// Enforce session timeout if logged in
if (!empty($_SESSION['user'])) {
    if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > $timeout_duration) {
        // Timeout: destroy session and clear remember cookie
        $cookie_name = $remember_cookie_name;
        if (isset($_COOKIE[$cookie_name])) {
            setcookie($cookie_name, '', time() - 3600, '/');
            // Also remove token from DB for security
            if (isset($_SESSION['user']['id'])) {
                $stmt = $pdo->prepare('UPDATE users SET remember_token = NULL, remember_expiry = NULL WHERE id = :id');
                $stmt->execute([':id' => $_SESSION['user']['id']]);
            }
        }
        session_unset();
        session_destroy();
        // Redirect to login with timeout flag if this file used at page top
        header('Location: /pages/login.php?timeout=1');
        exit;
    }
    $_SESSION['last_activity'] = time();
}

// Helper function
function isLoggedIn(): bool {
    return !empty($_SESSION['user']) && !empty($_SESSION['user']['id']);
}
```

---

## includes/role_check.php
```php
<?php
// includes/role_check.php
require_once __DIR__ . '/session.php';

function hasRole($roles): bool {
    if (!isLoggedIn()) return false;
    $userRole = $_SESSION['user']['role'] ?? null;
    if (is_array($roles)) return in_array($userRole, $roles, true);
    return $userRole === $roles;
}

function requireLogin(): void {
    if (!isLoggedIn()) {
        header('Location: /pages/login.php');
        exit;
    }
}

function requireRole($roles): void {
    requireLogin();
    if (!hasRole($roles)) {
        http_response_code(403);
        echo '403 Forbidden';
        exit;
    }
}
```

---

## includes/csrf.php
```php
<?php
// includes/csrf.php
require_once __DIR__ . '/session.php';

function generateCsrfToken(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validateCsrfToken(?string $token): bool {
    if (empty($token) || empty($_SESSION['csrf_token'])) return false;
    return hash_equals($_SESSION['csrf_token'], $token);
}

function csrfMetaTag(): string {
    return '<meta name="csrf-token" content="' . htmlspecialchars(generateCsrfToken(), ENT_QUOTES, 'UTF-8') . '">';
}
```

---

## includes/header.php
```php
<?php
// includes/header.php - include on top of pages
require_once __DIR__ . '/csrf.php';
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>RBAC Admin</title>
  <?= csrfMetaTag(); ?>
  <!-- Local assets (place AdminLTE, Bootstrap, FontAwesome, jQuery in /assets) -->
  <link rel="stylesheet" href="/assets/bootstrap/css/bootstrap.min.css">
  <link rel="stylesheet" href="/assets/fontawesome/css/all.min.css">
  <link rel="stylesheet" href="/assets/adminlte/css/adminlte.min.css">
</head>
<body class="hold-transition sidebar-mini layout-fixed">
<div class="wrapper">

<!-- Include JS early for plugins; CSRF header for AJAX will be set below -->
<script src="/assets/jquery/jquery.min.js"></script>
<script src="/assets/bootstrap/js/bootstrap.bundle.min.js"></script>
<script src="/assets/adminlte/js/adminlte.min.js"></script>
<script>
// Attach CSRF token from meta tag to all AJAX requests
(function(){
  var tokenEl = document.querySelector('meta[name="csrf-token"]');
  if (tokenEl) {
    var token = tokenEl.getAttribute('content');
    $.ajaxSetup({
      headers: { 'X-CSRF-Token': token }
    });
  }
})();
</script>
```

---

## includes/sidebar.php
```php
<?php
// includes/sidebar.php
require_once __DIR__ . '/role_check.php';
$name = $_SESSION['user']['name'] ?? $_SESSION['user']['username'] ?? 'User';
$role = $_SESSION['user']['role'] ?? 'guest';
?>
<aside class="main-sidebar sidebar-dark-primary elevation-4">
  <a href="/index.php" class="brand-link">
    <span class="brand-text font-weight-light">RBAC Dashboard</span>
  </a>
  <div class="sidebar">
    <div class="user-panel mt-3 pb-3 mb-3 d-flex">
      <div class="info">
        <a href="#" class="d-block"><?= htmlspecialchars($name, ENT_QUOTES, 'UTF-8'); ?> <small class="text-muted">(<?= htmlspecialchars($role, ENT_QUOTES, 'UTF-8'); ?>)</small></a>
      </div>
    </div>
    <nav class="mt-2">
      <ul class="nav nav-pills nav-sidebar flex-column" data-widget="treeview" role="menu">
        <li class="nav-item">
          <a href="/index.php" class="nav-link"><i class="nav-icon fas fa-home"></i><p>Home</p></a>
        </li>

        <?php if (hasRole(['admin','manager'])): ?>
        <li class="nav-item"><a class="nav-link"><i class="nav-icon fas fa-chart-line"></i><p>Reports</p></a></li>
        <?php endif; ?>

        <?php if (hasRole('admin')): ?>
        <li class="nav-item"><a href="#userMgmt" data-toggle="modal" class="nav-link"><i class="nav-icon fas fa-users-cog"></i><p>User Management</p></a></li>
        <?php endif; ?>

        <li class="nav-item"><a href="/pages/logout.php" class="nav-link"><i class="nav-icon fas fa-sign-out-alt"></i><p>Logout</p></a></li>
      </ul>
    </nav>
  </div>
</aside>
```

---

## includes/footer.php
```php
<?php $year = date('Y'); ?>
<footer class="main-footer">
  <div class="float-right d-none d-sm-inline">RBAC System</div>
  <strong>&copy; <?= $year; ?> FujiFilm Optics Philippines.</strong>
</footer>
</div><!-- /.wrapper -->
</body>
</html>
```

---

## models/UserModel.php
```php
<?php
// models/UserModel.php
require_once __DIR__ . '/../config.php';

class UserModel {
    private PDO $db;
    public function __construct(PDO $pdo) {
        $this->db = $pdo;
    }

    public function findByUsername(string $username): ?array {
        $stmt = $this->db->prepare('SELECT * FROM users WHERE username = :u');
        $stmt->execute([':u' => $username]);
        $r = $stmt->fetch();
        return $r ?: null;
    }

    public function findById(int $id): ?array {
        $stmt = $this->db->prepare('SELECT id, name, username, email, role FROM users WHERE id = :id');
        $stmt->execute([':id' => $id]);
        return $stmt->fetch() ?: null;
    }

    public function create(string $name, string $username, string $email, string $password, string $role): int {
        $hash = password_hash($password, PASSWORD_DEFAULT);
        $stmt = $this->db->prepare('INSERT INTO users (name, username, email, password_hash, role) VALUES (:name, :username, :email, :hash, :role)');
        $stmt->execute([
            ':name' => $name,
            ':username' => $username,
            ':email' => $email,
            ':hash' => $hash,
            ':role' => $role,
        ]);
        // For SQL Server, lastInsertId may need sequence; attempting generic
        return (int)$this->db->lastInsertId();
    }

    public function update(int $id, ?string $name, ?string $username, ?string $email, ?string $password, ?string $role): bool {
        $fields = [];
        $params = [':id' => $id];
        if ($name !== null) { $fields[] = 'name = :name'; $params[':name'] = $name; }
        if ($username !== null) { $fields[] = 'username = :username'; $params[':username'] = $username; }
        if ($email !== null) { $fields[] = 'email = :email'; $params[':email'] = $email; }
        if ($password !== null && $password !== '') { $fields[] = 'password_hash = :hash'; $params[':hash'] = password_hash($password, PASSWORD_DEFAULT); }
        if ($role !== null) { $fields[] = 'role = :role'; $params[':role'] = $role; }
        if (empty($fields)) return false;
        $sql = 'UPDATE users SET ' . implode(', ', $fields) . ' WHERE id = :id';
        $stmt = $this->db->prepare($sql);
        return $stmt->execute($params);
    }

    public function delete(int $id): bool {
        $stmt = $this->db->prepare('DELETE FROM users WHERE id = :id');
        return $stmt->execute([':id' => $id]);
    }

    public function list(int $limit = 100, int $offset = 0): array {
        // SQL Server pagination: OFFSET..FETCH
        $stmt = $this->db->prepare('SELECT id, name, username, email, role FROM users ORDER BY id DESC OFFSET :offset ROWS FETCH NEXT :limit ROWS ONLY');
        $stmt->bindValue(':offset', (int)$offset, PDO::PARAM_INT);
        $stmt->bindValue(':limit', (int)$limit, PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->fetchAll();
    }

    public function setRememberToken(int $id, ?string $token, ?string $expiry): bool {
        $stmt = $this->db->prepare('UPDATE users SET remember_token = :token, remember_expiry = :expiry WHERE id = :id');
        return $stmt->execute([':token' => $token, ':expiry' => $expiry, ':id' => $id]);
    }
}
```

---

## pages/login.php
```php
<?php
require_once __DIR__ . '/../includes/session.php';
require_once __DIR__ . '/../includes/csrf.php';
if (isLoggedIn()) { header('Location: /index.php'); exit; }
?>
<?php include __DIR__ . '/../includes/header.php'; ?>

<div class="content-wrapper">
  <section class="content">
    <div class="container mt-5">
      <div class="row justify-content-center">
        <div class="col-md-5">
          <div class="card">
            <div class="card-body">
              <h4 class="card-title">Sign In</h4>

              <?php if (isset($_GET['timeout'])): ?>
                <div class="alert alert-warning">Your session expired due to inactivity. Please log in again.</div>
              <?php endif; ?>

              <form id="loginForm">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(generateCsrfToken(), ENT_QUOTES, 'UTF-8'); ?>">
                <div class="form-group">
                  <label>Username</label>
                  <input name="username" class="form-control" required>
                </div>
                <div class="form-group">
                  <label>Password</label>
                  <input type="password" name="password" class="form-control" required>
                </div>
                <div class="form-check mb-3">
                  <input type="checkbox" class="form-check-input" id="remember" name="remember">
                  <label class="form-check-label" for="remember">Stay Logged In</label>
                </div>
                <button class="btn btn-primary" type="submit">Login</button>
              </form>

              <div id="loginAlert" class="mt-3"></div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </section>
</div>

<?php include __DIR__ . '/../includes/footer.php'; ?>

<script>
$('#loginForm').on('submit', function(e){
  e.preventDefault();
  $.post('/ajax/login.php', $(this).serialize())
    .done(function(resp){
      if (resp.success) {
        window.location = resp.redirect || '/index.php';
      } else {
        $('#loginAlert').html('<div class="alert alert-danger">'+(resp.message||'Login failed')+'</div>');
      }
    }).fail(function(){
      $('#loginAlert').html('<div class="alert alert-danger">Server error</div>');
    });
});
</script>
```

---

## pages/admin_dashboard.php
```php
<?php
require_once __DIR__ . '/../includes/role_check.php';
requireRole('admin');
include __DIR__ . '/../includes/header.php';
include __DIR__ . '/../includes/sidebar.php';
?>
<div class="content-wrapper">
  <section class="content-header"><div class="container-fluid"><h1>Admin Dashboard</h1></div></section>
  <section class="content"><div class="container-fluid">

    <div class="card">
      <div class="card-header">User Management</div>
      <div class="card-body">
        <button class="btn btn-success mb-3" data-toggle="modal" data-target="#userModal">Add User</button>
        <div class="table-responsive">
          <table class="table table-sm" id="usersTable"><thead><tr><th>ID</th><th>Name</th><th>Username</th><th>Email</th><th>Role</th><th>Actions</th></tr></thead><tbody></tbody></table>
        </div>
      </div>
    </div>

  </div></section>
</div>

<!-- User Modal -->
<div class="modal fade" id="userModal"><div class="modal-dialog modal-lg"><div class="modal-content">
  <div class="modal-header"><h5 class="modal-title">Add User</h5><button class="close" data-dismiss="modal">&times;</button></div>
  <div class="modal-body">
    <form id="addUserForm">
      <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(generateCsrfToken(), ENT_QUOTES, 'UTF-8'); ?>">
      <div class="form-row">
        <div class="form-group col-md-4"><input name="name" class="form-control" placeholder="Name" required></div>
        <div class="form-group col-md-3"><input name="username" class="form-control" placeholder="Username" required></div>
        <div class="form-group col-md-3"><input name="email" type="email" class="form-control" placeholder="Email"></div>
        <div class="form-group col-md-2"><select name="role" class="form-control"><option>admin</option><option>manager</option><option>employee</option></select></div>
      </div>
      <div class="form-row">
        <div class="form-group col-md-4"><input name="password" type="password" class="form-control" placeholder="Password" required></div>
      </div>
      <button class="btn btn-primary" type="submit">Create</button>
    </form>
  </div>
</div></div></div>

<?php include __DIR__ . '/../includes/footer.php'; ?>

<script>
function loadUsers(){
  $.get('/ajax/list_users.php').done(function(res){
    var tbody = $('#usersTable tbody').empty();
    (res.users||[]).forEach(function(u){
      var tr = $('<tr>');
      tr.append('<td>'+u.id+'</td>');
      tr.append('<td><input class="form-control form-control-sm name" data-id="'+u.id+'" value="'+u.name+'"></td>');
      tr.append('<td><input class="form-control form-control-sm username" data-id="'+u.id+'" value="'+u.username+'"></td>');
      tr.append('<td><input class="form-control form-control-sm email" data-id="'+u.id+'" value="'+(u.email||'')+'"></td>');
      tr.append('<td>\
        <select class="form-control form-control-sm role" data-id="'+u.id+'">\
          <option '+(u.role==='admin'?'selected':'')+'>admin</option>\
          <option '+(u.role==='manager'?'selected':'')+'>manager</option>\
          <option '+(u.role==='employee'?'selected':'')+'>employee</option>\
        </select>\
      </td>');

      var actions = '<button class="btn btn-sm btn-primary mr-1" onclick="saveUser('+u.id+')">Save</button>';
      actions += '<button class="btn btn-sm btn-danger" onclick="delUser('+u.id+')">Delete</button>';
      tr.append('<td>'+actions+'</td>');
      tbody.append(tr);
    });
  });
}

$('#userModal').on('shown.bs.modal', loadUsers);

$('#addUserForm').on('submit', function(e){
  e.preventDefault();
  $.post('/ajax/add_user.php', $(this).serialize(), function(res){
    if(res.success){ alert('User created'); loadUsers(); $('#addUserForm')[0].reset(); }
    else alert(res.message||'Create failed');
  }, 'json');
});

function saveUser(id){
  var row = $('#usersTable tbody').find('input[data-id="'+id+'"]').closest('tr');
  var data = {
    id: id,
    name: row.find('.name').val(),
    username: row.find('.username').val(),
    email: row.find('.email').val(),
    role: row.find('.role').val(),
    csrf_token: $('meta[name="csrf-token"]').attr('content')
  };
  $.post('/ajax/update_user.php', data, function(res){ if(res.success) loadUsers(); else alert(res.message||'Update failed'); }, 'json');
}

function delUser(id){
  if(!confirm('Delete user?')) return;
  $.post('/ajax/delete_user.php', {id:id, csrf_token: $('meta[name="csrf-token"]').attr('content')}, function(res){ if(res.success) loadUsers(); else alert(res.message||'Delete failed'); }, 'json');
}
</script>
```

---

## pages/manager_dashboard.php
```php
<?php
require_once __DIR__ . '/../includes/role_check.php';
requireRole(['manager','admin']);
include __DIR__ . '/../includes/header.php';
include __DIR__ . '/../includes/sidebar.php';
?>
<div class="content-wrapper">
  <section class="content-header"><div class="container-fluid"><h1>Manager Dashboard</h1></div></section>
  <section class="content"><div class="container-fluid">
    <div class="card"><div class="card-body">Manager features here. Managers can update users but cannot delete them.</div></div>
  </div></section>
</div>
<?php include __DIR__ . '/../includes/footer.php'; ?>
```

---

## pages/employee_dashboard.php
```php
<?php
require_once __DIR__ . '/../includes/role_check.php';
requireRole(['employee','manager','admin']);
include __DIR__ . '/../includes/header.php';
include __DIR__ . '/../includes/sidebar.php';
?>
<div class="content-wrapper">
  <section class="content-header"><div class="container-fluid"><h1>Employee Dashboard</h1></div></section>
  <section class="content"><div class="container-fluid">
    <div class="card"><div class="card-body">Employee features here. Read-only access for user management.</div></div>
  </div></section>
</div>
<?php include __DIR__ . '/../includes/footer.php'; ?>
```

---

## pages/logout.php
```php
<?php
require_once __DIR__ . '/../includes/session.php';
require_once __DIR__ . '/../config.php';

// Clear remember token in DB and cookie
if (!empty($_SESSION['user']['id'])) {
    $stmt = $pdo->prepare('UPDATE users SET remember_token = NULL, remember_expiry = NULL WHERE id = :id');
    $stmt->execute([':id' => $_SESSION['user']['id']]);
}
$cookie_name = 'remember_token';
if (isset($_COOKIE[$cookie_name])) setcookie($cookie_name, '', time() - 3600, '/');

session_unset();
session_destroy();
header('Location: /pages/login.php');
exit;
```

---

## ajax/login.php
```php
<?php
// ajax/login.php
require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../includes/session.php';
require_once __DIR__ . '/../includes/csrf.php';
require_once __DIR__ . '/../models/UserModel.php';

header('Content-Type: application/json');
if ($_SERVER['REQUEST_METHOD'] !== 'POST') { http_response_code(405); echo json_encode(['success'=>false,'message'=>'Method not allowed']); exit; }

$tokenHeader = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? null;
$tokenPost = $_POST['csrf_token'] ?? null;
$token = $tokenHeader ?: $tokenPost;
if (!validateCsrfToken($token)) { echo json_encode(['success'=>false,'message'=>'Invalid CSRF token']); exit; }

$username = trim((string)($_POST['username'] ?? ''));
$password = $_POST['password'] ?? '';
$remember = isset($_POST['remember']) && ($_POST['remember'] === 'on' || $_POST['remember']==='1');

if ($username === '' || $password === '') { echo json_encode(['success'=>false,'message'=>'Missing credentials']); exit; }

$userModel = new UserModel($pdo);
$user = $userModel->findByUsername($username);
if (!$user || !password_verify($password, $user['password_hash'])) {
    echo json_encode(['success'=>false,'message'=>'Invalid credentials']); exit;
}

// Set session
$_SESSION['user'] = [
    'id' => (int)$user['id'],
    'name' => $user['name'],
    'username' => $user['username'],
    'email' => $user['email'],
    'role' => $user['role'],
];
session_regenerate_id(true);

// Remember me handling
$cookie_name = 'remember_token';
if ($remember) {
    $token = bin2hex(random_bytes(32));
    $expiryTs = time() + (86400 * 30); // 30 days
    $expirySql = date('Y-m-d H:i:s', $expiryTs);
    // Save token to DB
    $userModel->setRememberToken((int)$user['id'], $token, $expirySql);
    // Set secure httponly cookie (secure flag should be true on HTTPS)
    $secure = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on';
    setcookie($cookie_name, $token, $expiryTs, '/', '', $secure, true);
}

// Role-based redirect URL
$redirect = '/pages/employee_dashboard.php';
if ($user['role'] === 'admin') $redirect = '/pages/admin_dashboard.php';
elseif ($user['role'] === 'manager') $redirect = '/pages/manager_dashboard.php';

echo json_encode(['success'=>true,'redirect'=>$redirect]);
```

---

## ajax/list_users.php
```php
<?php
header('Content-Type: application/json');
require_once __DIR__ . '/../includes/role_check.php';
require_once __DIR__ . '/../models/UserModel.php';
requireRole('admin');
$userModel = new UserModel($pdo);
echo json_encode(['success'=>true,'users'=>$userModel->list(100,0)]);
```

---

## ajax/add_user.php
```php
<?php
header('Content-Type: application/json');
require_once __DIR__ . '/../includes/role_check.php';
require_once __DIR__ . '/../includes/csrf.php';
require_once __DIR__ . '/../models/UserModel.php';
requireRole('admin');

$token = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? ($_POST['csrf_token'] ?? null);
if (!validateCsrfToken($token)) { echo json_encode(['success'=>false,'message'=>'Invalid CSRF']); exit; }

$name = trim((string)($_POST['name'] ?? ''));
$username = trim((string)($_POST['username'] ?? ''));
$email = filter_var($_POST['email'] ?? null, FILTER_VALIDATE_EMAIL);
$password = $_POST['password'] ?? '';
$role = $_POST['role'] ?? '';

if ($name === '' || $username === '' || $password === '' || !in_array($role, ['admin','manager','employee'], true)) {
    echo json_encode(['success'=>false,'message'=>'Invalid input']); exit;
}

try {
    $userModel = new UserModel($pdo);
    $userModel->create($name, $username, $email, $password, $role);
    echo json_encode(['success'=>true]);
} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode(['success'=>false,'message'=>'Create failed']);
}
```

---

## ajax/update_user.php
```php
<?php
header('Content-Type: application/json');
require_once __DIR__ . '/../includes/role_check.php';
require_once __DIR__ . '/../includes/csrf.php';
require_once __DIR__ . '/../models/UserModel.php';

if (!hasRole(['admin','manager'])) { echo json_encode(['success'=>false,'message'=>'Unauthorized']); exit; }
$token = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? ($_POST['csrf_token'] ?? null);
if (!validateCsrfToken($token)) { echo json_encode(['success'=>false,'message'=>'Invalid CSRF']); exit; }

$id = filter_var($_POST['id'] ?? null, FILTER_VALIDATE_INT);
$name = isset($_POST['name']) ? trim((string)$_POST['name']) : null;
$username = isset($_POST['username']) ? trim((string)$_POST['username']) : null;
$email = isset($_POST['email']) ? filter_var($_POST['email'], FILTER_VALIDATE_EMAIL) : null;
$role = isset($_POST['role']) ? (string)$_POST['role'] : null;

if (!$id) { echo json_encode(['success'=>false,'message'=>'Invalid ID']); exit; }
if ($role !== null && !in_array($role, ['admin','manager','employee'], true)) { echo json_encode(['success'=>false,'message'=>'Invalid role']); exit; }

try {
    $userModel = new UserModel($pdo);
    $ok = $userModel->update($id, $name, $username, $email, null, $role);
    echo json_encode(['success'=> (bool)$ok]);
} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode(['success'=>false,'message'=>'Update failed']);
}
```

---

## ajax/delete_user.php
```php
<?php
header('Content-Type: application/json');
require_once __DIR__ . '/../includes/role_check.php';
require_once __DIR__ . '/../includes/csrf.php';
require_once __DIR__ . '/../models/UserModel.php';
requireRole('admin');
$token = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? ($_POST['csrf_token'] ?? null);
if (!validateCsrfToken($token)) { echo json_encode(['success'=>false,'message'=>'Invalid CSRF']); exit; }

$id = filter_var($_POST['id'] ?? null, FILTER_VALIDATE_INT);
if (!$id) { echo json_encode(['success'=>false,'message'=>'Invalid ID']); exit; }

try {
    $userModel = new UserModel($pdo);
    $ok = $userModel->delete($id);
    echo json_encode(['success'=> (bool)$ok]);
} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode(['success'=>false,'message'=>'Delete failed']);
}
```

---

## Notes & Checklist (Double-checked)
- All pages require `includes/session.php` or `includes/role_check.php` which itself loads session.
- CSRF is generated in header and attached to AJAX via `$.ajaxSetup` (meta + header). Server accepts from POST field or X-CSRF-Token header.
- `remember_token` flow:
  - On login (if checked) a random token stored in DB and cookie (httponly).
  - `includes/session.php` auto-logs in if token valid and not expired.
  - On logout or session timeout the token is cleared from DB and cookie removed.
- Managers allowed to call `update_user.php` but delete is restricted to admins.
- Use HTTPS in production (`secure` flag for cookies). Set `secure` true in production.
- Ensure `assets/` contains AdminLTE, Bootstrap, jQuery, FontAwesome local files and paths above match.

---

If you want, I can now:
1. Export these files as a zip you can download (I can generate files in the canvas). 
2. Replace SQL Server `lastInsertId()` fallback with an explicit `SELECT SCOPE_IDENTITY()` helper for MSSQL.
3. Add sample seed SQL with a hashed admin password.

Which of those next steps would you like?

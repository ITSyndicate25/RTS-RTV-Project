Php + Admin Lte Rbac Dashboard (mssql, Pdo, Csrf, Ajax) – Complete Starter Codebase
· other
# PHP + AdminLTE RBAC Dashboard (MSSQL, PDO, CSRF, AJAX) — Complete Codebase
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
- Ensure `assets/` contains AdminLTE, Bootstrap, jQuery, FontAwesome local files and paths above ma
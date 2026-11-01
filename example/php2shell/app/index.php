<?php
// Maintainer: Constanze Roedig <constanze.roedig@gmail.com>
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0; see LICENSE.
// All trademarks are expressly reserved.
//
// Innocent CI build-artifact uploader. This is a plausible workload a runner
// would build and serve; it contains no vulnerability of its own. It starts a
// session and renders an upload form with the PHP_SESSION_UPLOAD_PROGRESS field
// so the browser can poll progress — the ordinary, legitimate reason
// session.upload_progress is active. The RCE lives in PHP core, not here.
session_start();
$dir = __DIR__ . '/uploads';
$files = is_dir($dir) ? array_values(array_filter(scandir($dir), fn($f) => $f[0] !== '.')) : [];
?>
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>CI Artifact Uploader</title></head>
<body>
<h1>CI Artifact Uploader</h1>
<p>Upload a build artifact from the pipeline.</p>
<form action="upload.php" method="post" enctype="multipart/form-data">
  <input type="hidden" name="<?= ini_get('session.upload_progress.name') ?>" value="ci-artifact">
  <input type="file" name="artifact">
  <button type="submit">Upload</button>
</form>
<h2>Stored artifacts</h2>
<ul>
<?php foreach ($files as $f): ?>
  <li><?= htmlspecialchars($f, ENT_QUOTES) ?></li>
<?php endforeach; ?>
</ul>
</body>
</html>

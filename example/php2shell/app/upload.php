<?php
// Maintainer: Constanze Roedig <constanze.roedig@gmail.com>
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0; see LICENSE.
// All trademarks are expressly reserved.
//
// Innocent upload handler: stores the posted artifact and returns to the index.
// No eval, no shell, no deserialization — the app is not the vulnerability.
// The PHP2Shell RCE is reached by PHP core while parsing the multipart body
// (session.upload_progress), before this handler ever runs.
session_start();
$dir = __DIR__ . '/uploads';
if (!is_dir($dir)) {
    mkdir($dir, 0775, true);
}
if (!empty($_FILES['artifact']['tmp_name']) && is_uploaded_file($_FILES['artifact']['tmp_name'])) {
    $name = basename($_FILES['artifact']['name']);
    $name = preg_replace('/[^A-Za-z0-9._-]/', '_', $name);
    move_uploaded_file($_FILES['artifact']['tmp_name'], $dir . '/' . $name);
}
header('Location: index.php');
echo "artifact received\n";

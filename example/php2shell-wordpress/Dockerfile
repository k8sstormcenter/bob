# Maintainer: Constanze Roedig <constanze.roedig@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE.
# All trademarks are expressly reserved.

FROM php:8.4.26-apache@sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a

ARG WP_VERSION=7.1.4
ARG WP_SHA1=b175879c4fb2d35300f9abe1153da9b543a35a2b
ARG WPCLI_VERSION=2.12.0
ARG WPCLI_SHA512=be928f6b8ca1e8dfb9d2f4b75a13aa4aee0896f8a9a0a1c45cd5d2c98605e6172e6d014dda2e27f88c98befc16c040cbb2bd1bfa121510ea5cdf5f6a30fe8832

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends imagemagick webp jpegoptim optipng libimage-exiftool-perl; \
    rm -rf /var/lib/apt/lists/*; \
    docker-php-ext-install mysqli; \
    curl -fsSL -o /tmp/wp.tgz "https://wordpress.org/wordpress-${WP_VERSION}.tar.gz"; \
    echo "${WP_SHA1}  /tmp/wp.tgz" | sha1sum -c -; \
    tar -xzf /tmp/wp.tgz -C /var/www/html --strip-components=1; \
    rm /tmp/wp.tgz; \
    curl -fsSL -o /usr/local/bin/wp "https://github.com/wp-cli/wp-cli/releases/download/v${WPCLI_VERSION}/wp-cli-${WPCLI_VERSION}.phar"; \
    echo "${WPCLI_SHA512}  /usr/local/bin/wp" | sha512sum -c -; \
    chmod 0755 /usr/local/bin/wp

COPY conf/php.ini /usr/local/etc/php/conf.d/zz-php2shell.ini
COPY conf/apache-prefork.conf /etc/apache2/mods-available/mpm_prefork.conf
COPY app/wp-config.php /var/www/html/wp-config.php
COPY app/mu-plugins/ /var/www/html/wp-content/mu-plugins/

RUN set -eux; \
    a2dismod mpm_event 2>/dev/null || true; \
    a2enmod mpm_prefork rewrite; \
    mkdir -p /var/www/html/uploads /var/www/html/wp-content/uploads; \
    chown -R www-data:www-data /var/www/html

EXPOSE 80

#!/usr/bin/env bash
# gelistirici:/opt/scripts/mkwp

# Configuration
WP_CONF="${WP_CONF:-./wp.conf}"

warn() {
    echo >&2 "$*"
}

run() {
    warn "$*"
    "$@"
}

die() {
    warn "$*"
    exit 1
}

generate_password() {
    tr -dc A-Za-z0-9 < /dev/urandom | head -c $1 |xargs
}

mysql_sudo() {
    local mysql_host="${WP_MYSQL_HOST:-localhost}"
    local mysql_port="${WP_MYSQL_PORT:-3306}"

    if [[ -z "$WP_MYSQL_SUUSER" ]]; then
    die "MySQL database user informations \`${WP_CONF}' files cannot reach."
    fi

    mysql --host="$mysql_host" --port "$mysql_port" \
      --user="$WP_MYSQL_SUUSER" "$@"
}

vagrant(){
    su - vagrant -c "$@"
}

install_mariadb() {

    yum install -y mariadb-server && systemctl start mariadb && systemctl enable mariadb
    MYSQL=""
    SECURE_MYSQL=$(expect -c "
    set timeout 10
    spawn mysql_secure_installation
    #expect \"Enter current password for root (enter for none):\"
    send \"$MYSQL\r\"
    #expect \Set root password? [Y/n]\"
    send \"Y\r\"
    #expect \New password:\"
    send \"${WP_MYSQL_SUPASS}\r\"
    #expect \Re-enter new password:\"
    send \"${WP_MYSQL_SUPASS}\r\"
    #expect \"Remove anonymous users?\"
    send \"y\r\"
    #expect \"Disallow root login remotely?\"
    send \"y\r\"
    #expect \"Remove test database and access to it?\"
    send \"y\r\"
    #expect \"Reload privilege tables now?\"
    send \"y\r\"
    expect eof
    ")
    echo "$SECURE_MYSQL"

    echo "[client]
    user=${WP_MYSQL_SUUSER}
    password=${WP_MYSQL_SUPASS}" > "/root/.my.cnf"
}




install_nginx() {
    yum install -y nginx && systemctl enable nginx && systemctl start nginx
    systemctl start firewalld && firewall-cmd --permanent --zone=public  --add-service=http && firewall-cmd --permanent --add-port=443/tcp && firewall-cmd --reload
}

install_php() {
    rpm -Uvh https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm && yum install -y https://rpms.remirepo.net/enterprise/remi-release-8.rpm && yum module enable php:remi-7.3 -y && yum install -y php php-cli php-common php-fpm php-mysqlnd php-dom php-simplexml php-ssh2 php-xml php-xmlreader php-curl php-date php-exif php-filter php-ftp php-gd php-hash php-iconv php-json php-libxml php-pecl-imagick php-mbstring php-mysqlnd php-openssl php-pcre php-posix php-sockets php-spl php-tokenizer php-zlib
}

install_wp_cli() {
    curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar && chmod +x wp-cli.phar && mv wp-cli.phar /usr/bin/wp
}

install_certbot() {
    curl -O https://dl.eff.org/certbot-auto && chmod 0755 certbot-auto && mv certbot-auto /usr/bin/certbot-auto && certbot-auto --nginx -d ${DOMAIN}
}

check_environment() {
    # Better safe than sorry
    [[ $EUID == 0 ]] || die "Only Root user can use this script."

    # Check configuration
    for env in WP_{ROOT,NGINX_CONFIG,PHPFPM_CONFIG} \
        WP_MYSQL_{HOST,PORT,SUUSER,SUPASS} ; do
    [[ -n "${!env}" ]] || die "Setting ${env} wp setting file is not defined in \`${WP_CONF}'"
    done

    # Check MySQL username length (max length is 16)
    export WP_MYSQL_USERNAME="${WP_NAME}"
    if [[ ${#WP_MYSQL_USERNAME} -gt 16 ]]; then
    die "MySQL username \`${WP_MYSQL_USERNAME}' contains more than 16 characters."
    fi
    export WP_MYSQL_DATABASE="${WP_NAME}"

    [[ -d "$WP_ROOT" ]] || die "WP root directory \'${WP_ROOT}' is not directory"
    pushd "$WP_ROOT" &>/dev/null

    export WP_WEBROOT="${WP_ROOT}"
      
    export WP_DOMAIN="${DOMAIN}"
}

configure_phpfpm(){
    warn "Configuring PHP-FPM pool..."
    echo -e "[site]
listen = ${WP_FASTCGI_PASS}

user = php-fpm
group = php-fpm

request_slowlog_timeout = 5s
slowlog = ${WP_PHPFPM_LOG_ROOT}/${WP_NAME}-slowlog.log
listen.allowed_clients = 127.0.0.1

pm = dynamic

pm.max_children = 5
pm.start_servers = 3
pm.min_spare_servers = 2
pm.max_spare_servers = 4
pm.max_requests = 200

listen.backlog = -1

pm.status_path = /status

request_terminate_timeout = 120s
rlimit_files = 131072
rlimit_core = unlimited
catch_workers_output = yes

env[HOSTNAME] = $HOSTNAME
env[TMP] = /tmp
env[TMPDIR] = /tmp
env[TEMP] = /tmp

;php_admin_value[sendmail_path] = /usr/sbin/sendmail -t -i -f www@my.domain.com
;php_flag[display_errors] = off
php_admin_value[error_log] = ${WP_PHPFPM_LOG_ROOT}/${WP_NAME}-error.log
php_admin_flag[log_errors] = on
;php_admin_value[memory_limit] = 128M

php_value[session.save_handler] = files
php_value[session.save_path]    = /tmp/session
php_value[soap.wsdl_cache_dir]  = /tmp/wsdlcache
;php_value[opcache.file_cache]  = /tmp/opcache" > "${WP_PHPFPM_CONFIG}/${WP_NAME}.conf"

  [[ $? == 0 ]] || die "PHP-FPM settings is not working."
}


create_htaccess() {
  warn "creating... .htaccess"

  echo -e "<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase //
RewriteRule ^index\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>"> "$WP_WEBROOT/.htaccess"
      
  chown vagrant:vagrant "$WP_WEBROOT/.htaccess"

  [[ $? == 0 ]] || die ".htaccess could not created."
}


create_wp() {
    testlink=$(basename "${WP_UPLOADS}" .tar.gz)
    local db_name="t_$(echo "${WP_MYSQL_DATABASE}" | tr '-' '_')" 
    local db_user="t_$(echo "${WP_MYSQL_USERNAME}" | tr '-' '_')" 
    local db_pass="$(generate_password 16)"
    HTTP_PASS="$(generate_password 16)"
    ADMIN_PASS="$(generate_password 16)"

    warn "Database \`${db_name}' creating..."
    mysql_sudo -e "create database "$db_name" character set utf8 collate utf8_turkish_ci"
    [[ $? == 0 ]] || die "Database \`${db_name}' is not created."

    warn "Grating privileges to \`$db_user' "
    mysql_sudo -e "grant all privileges on "$db_name".* to "$db_user"@localhost identified by \"$db_pass\""
    [[ $? == 0 ]] || die "\`$db_user' privileges granted."
      
    chown vagrant:vagrant $WP_WEBROOT  

    if [[ $VERSION == "son" ]];
      then
        vagrant "cd $WP_WEBROOT &&
        wp core download --locale=en_US"
      else
        vagrant "cd $WP_WEBROOT &&
        wp core download --version=$VERSION --locale=en_US"
      fi

    vagrant "cd $WP_WEBROOT &&
    wp core config --dbname=$db_name --dbuser=$db_user --dbpass=$db_pass &&
    wp core install --url="http://${WP_DOMAIN}" --title=$WP_NAME --admin_user=vagrant --admin_password=$ADMIN_PASS --admin_email=email@example.org"
      
    [[ -d "$WP_WEBROOT/wp-content/uploads" ]] || mkdir "$WP_WEBROOT/wp-content/uploads"
    chown -R nginx:nginx "$WP_WEBROOT/wp-content/uploads"
      
    echo -e "<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
RewriteRule ^index\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>"> "$WP_WEBROOT/.htaccess"
      
    chown vagrant:vagrant "$WP_WEBROOT/.htaccess"
      
    vagrant "cd $WP_WEBROOT &&
    wp user create vagrant email@example.org --role=administrator --user_pass=Kid32do${WP_NAME} --display_name='Özgür Yazılım' --first_name=Ozgur --last_name=Yazilim &&
    cd $WP_WEBROOT/wp-content/themes" 2>/dev/null
} 


update_wp_sites() {
       echo -e "${WP_WEBROOT}\t${WP_DOMAIN}" >> /opt/scripts/wp_sites.txt
}

install_webmin() {
    dnf update -y && wget https://prdownloads.sourceforge.net/webadmin/webmin-1.930-1.noarch.rpm && dnf install -y perl perl-Net-SSLeay openssl perl-Encode-Detect && rpm -ivh webmin-1.930-1.noarch.rpm
}

install_postfix() {
    dnf install -y postfix && systemctl enable postfix; systemctl start postfix
}

configure_postfix() {
    echo -e "# See /usr/share/postfix/main.cf.dist for a commented, more complete version


# Debian specific:  Specifying a file name will cause the first
# line of that file to be used as the name.  The Debian default
# is /etc/mailname.
#myorigin = /etc/mailname

smtpd_banner = $myhostname ESMTP
biff = no

# appending .domain is the MUA's job.
append_dot_mydomain = no

# Uncomment the next line to generate "delayed mail" warnings
#delay_warning_time = 4h

readme_directory = no

# See http://www.postfix.org/COMPATIBILITY_README.html -- default to 2 on
# fresh installs.
compatibility_level = 2

# TLS parameters
smtpd_tls_cert_file = /etc/ssl/certs/ssl-cert-snakeoil.pem
smtpd_tls_key_file = /etc/ssl/private/ssl-cert-snakeoil.key
smtpd_use_tls=yes
smtpd_tls_session_cache_database = btree:${data_directory}/smtpd_scache
smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache

# See /usr/share/doc/postfix/TLS_README.gz in the postfix-doc package for
# information on enabling SSL in the smtp client.

smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated defer_unauth_destination
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
mydestination = 
relayhost = ${POSTFIX_RELAYHOST_IP}
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
mailbox_size_limit = 0
recipient_delimiter = +
inet_interfaces = loopback-only
inet_protocols = ipv4
myhostname = ${DOMAIN}
myorigin = /etc/mailname
mynetworks_style = subnet
smtp_sasl_auth_enable = yes
smtpd_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/smtp_sasl_password_map
smtp_sasl_security_options = noanonymous" > "/etc/postfix/main.cf"

echo -e "#
# Postfix master process configuration file.  For details on the format
# of the file, see the master(5) manual page (command: "man 5 master" or
# on-line: http://www.postfix.org/master.5.html).
#
# Do not forget to execute "postfix reload" after editing this file.
#
# ==========================================================================
# service type  private unpriv  chroot  wakeup  maxproc command + args
#               (yes)   (yes)   (no)    (never) (100)
# ==========================================================================
smtp      inet  n       -       y       -       -       smtpd
#smtp      inet  n       -       y       -       1       postscreen
#smtpd     pass  -       -       y       -       -       smtpd
#dnsblog   unix  -       -       y       -       0       dnsblog
#tlsproxy  unix  -       -       y       -       0       tlsproxy
#submission inet n       -       y       -       -       smtpd
#  -o syslog_name=postfix/submission
#  -o smtpd_tls_security_level=encrypt
#  -o smtpd_sasl_auth_enable=yes
#  -o smtpd_reject_unlisted_recipient=no
#  -o smtpd_client_restrictions=$mua_client_restrictions
#  -o smtpd_helo_restrictions=$mua_helo_restrictions
#  -o smtpd_sender_restrictions=$mua_sender_restrictions
#  -o smtpd_recipient_restrictions=
#  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject
#  -o milter_macro_daemon_name=ORIGINATING
#smtps     inet  n       -       y       -       -       smtpd
#  -o syslog_name=postfix/smtps
#  -o smtpd_tls_wrappermode=yes
#  -o smtpd_sasl_auth_enable=yes
#  -o smtpd_reject_unlisted_recipient=no
#  -o smtpd_client_restrictions=$mua_client_restrictions
#  -o smtpd_helo_restrictions=$mua_helo_restrictions
#  -o smtpd_sender_restrictions=$mua_sender_restrictions
#  -o smtpd_recipient_restrictions=
#  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject
#  -o milter_macro_daemon_name=ORIGINATING
#628       inet  n       -       y       -       -       qmqpd
pickup    unix  n       -       y       60      1       pickup
cleanup   unix  n       -       y       -       0       cleanup
qmgr      unix  n       -       n       300     1       qmgr
#qmgr     unix  n       -       n       300     1       oqmgr
tlsmgr    unix  -       -       y       1000?   1       tlsmgr
rewrite   unix  -       -       y       -       -       trivial-rewrite
bounce    unix  -       -       y       -       0       bounce
defer     unix  -       -       y       -       0       bounce
trace     unix  -       -       y       -       0       bounce
verify    unix  -       -       y       -       1       verify
flush     unix  n       -       y       1000?   0       flush
proxymap  unix  -       -       n       -       -       proxymap
proxywrite unix -       -       n       -       1       proxymap
smtp      unix  -       -       y       -       -       smtp
relay     unix  -       -       y       -       -       smtp
#       -o smtp_helo_timeout=5 -o smtp_connect_timeout=5
showq     unix  n       -       y       -       -       showq
error     unix  -       -       y       -       -       error
retry     unix  -       -       y       -       -       error
discard   unix  -       -       y       -       -       discard
local     unix  -       n       n       -       -       local
virtual   unix  -       n       n       -       -       virtual
lmtp      unix  -       -       y       -       -       lmtp
anvil     unix  -       -       y       -       1       anvil
scache    unix  -       -       y       -       1       scache
#
# ====================================================================
# Interfaces to non-Postfix software. Be sure to examine the manual
# pages of the non-Postfix software to find out what options it wants.
#
# Many of the following services use the Postfix pipe(8) delivery
# agent.  See the pipe(8) man page for information about ${recipient}
# and other message envelope options.
# ====================================================================
#
# maildrop. See the Postfix MAILDROP_README file for details.
# Also specify in main.cf: maildrop_destination_recipient_limit=1
#
maildrop  unix  -       n       n       -       -       pipe
  flags=DRhu user=vmail argv=/usr/bin/maildrop -d ${recipient}
#
# ====================================================================
#
# Recent Cyrus versions can use the existing "lmtp" master.cf entry.
#
# Specify in cyrus.conf:
#   lmtp    cmd="lmtpd -a" listen="localhost:lmtp" proto=tcp4
#
# Specify in main.cf one or more of the following:
#  mailbox_transport = lmtp:inet:localhost
#  virtual_transport = lmtp:inet:localhost
#
# ====================================================================
#
# Cyrus 2.1.5 (Amos Gouaux)
# Also specify in main.cf: cyrus_destination_recipient_limit=1
#
#cyrus     unix  -       n       n       -       -       pipe
#  user=cyrus argv=/cyrus/bin/deliver -e -r ${sender} -m ${extension} ${user}
#
# ====================================================================
# Old example of delivery via Cyrus.
#
#old-cyrus unix  -       n       n       -       -       pipe
#  flags=R user=cyrus argv=/cyrus/bin/deliver -e -m ${extension} ${user}
#
# ====================================================================
#
# See the Postfix UUCP_README file for configuration details.
#
uucp      unix  -       n       n       -       -       pipe
  flags=Fqhu user=uucp argv=uux -r -n -z -a$sender - $nexthop!rmail ($recipient)
#
# Other external delivery methods.
#
ifmail    unix  -       n       n       -       -       pipe
  flags=F user=ftn argv=/usr/lib/ifmail/ifmail -r $nexthop ($recipient)
bsmtp     unix  -       n       n       -       -       pipe
  flags=Fq. user=bsmtp argv=/usr/lib/bsmtp/bsmtp -t$nexthop -f$sender $recipient
scalemail-backend unix  -   n   n   -   2   pipe
  flags=R user=scalemail argv=/usr/lib/scalemail/bin/scalemail-store ${nexthop} ${user} ${extension}
mailman   unix  -       n       n       -       -       pipe
  flags=FR user=list argv=/usr/lib/mailman/bin/postfix-to-mailman.py
  ${nexthop} ${user}" > "etc/postfix/master.cf"
}

[[ -e "${WP_CONF}" ]] || die "WP configuration file \`${WP_CONF}' is empty."
source "${WP_CONF}" || die "WP configuration file \`${WP_CONF} wrong."


if [[ -n "$WP_NAME" && -n "$VERSION" ]]; then
    install_mariadb
    install_nginx
    install_php
    install_wp_cli
    check_environment
    create_wp
    configure_nginx
    create_htaccess
    update_wp_sites
    install_webmin
    install_certbot
    install_postfix
    echo "Wordpress installation completed."
fi
# Reload configuration
systemctl restart php-fpm >/dev/null 2>&1
systemctl reload nginx >/dev/null 2>&1
# Give some useful info
echo "Script completed."
echo "You can visit http://${DOMAIN}"
echo "Admin Password: admin / $ADMIN_PASS"
echo "Vagrant Password: Vagrant / Kid32do${WP_NAME}"

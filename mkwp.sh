#!/usr/bin/env bash
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

user(){
    su - ${user} -c "$@"
}

prepare() {
    setenforce 0
}

install_mariadb() {

    yum install -y mariadb-server && systemctl start mariadb && systemctl enable mariadb && yum install -y expect
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
    systemctl start firewalld && firewall-cmd --permanent --zone=public  --add-service=http && firewall-cmd --permanent --zone=public --add-service=https && firewall-cmd --reload
    iptables -I INPUT -p tcp -m tcp --dport 80 -j ACCEPT && iptables -I INPUT -p tcp -m tcp --dport 443 -j ACCEPT
    mkdir -p /var/www/html/wordpress
}

install_php() {
    rpm -Uvh https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm && yum install -y https://rpms.remirepo.net/enterprise/remi-release-8.rpm && yum module enable php:remi-7.3 -y && yum install -y php php-cli php-common php-fpm php-mysqlnd php-dom php-simplexml php-ssh2 php-xml php-xmlreader php-curl php-date php-exif php-filter php-ftp php-gd php-hash php-iconv php-json php-libxml php-pecl-imagick php-mbstring php-mysqlnd php-openssl php-pcre php-posix php-sockets php-spl php-tokenizer php-zlib
}

install_wp_cli() {
    curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar && chmod +x wp-cli.phar && mv wp-cli.phar /usr/bin/wp
}

install_ssl() {
#    curl -O https://dl.eff.org/certbot-auto && chmod 0755 certbot-auto && mv certbot-auto /usr/bin/certbot-auto && certbot-auto --nginx -d ${DOMAIN}
    echo "empty for now"
}
install_ssl_locale() {
    mkdir -p /etc/pki/nginx/private/ && openssl req -newkey rsa:2048 -nodes -keyout /etc/pki/nginx/private/server.key -x509 -days 365 -out /etc/pki/nginx/server.crt
}

configure_nginx() {
echo -e 'user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log;
pid /run/nginx.pid;

include /usr/share/nginx/modules/*.conf;

events {
worker_connections 1024;
}

http {

sendfile            on;
tcp_nopush          on;
tcp_nodelay         on;
keepalive_timeout   65;
types_hash_max_size 2048;

include             /etc/nginx/mime.types;
default_type        application/octet-stream;
include /etc/nginx/conf.d/*.conf;

server {
        listen 80 default_server;
        listen [::]:80 default_server;
        server_name test.com;
        return 301 https://$server_name$request_uri;
}

server {
listen       443 ssl http2 default_server;
listen       [::]:443 ssl http2 default_server;
server_name  test.coms;
root         /usr/share/nginx/html;

ssl_certificate "/etc/pki/nginx/server.crt";
        ssl_certificate_key "/etc/pki/nginx/private/server.key";
        ssl_session_cache shared:SSL:1m;
        ssl_session_timeout  10m;
        ssl_ciphers PROFILE=SYSTEM;
        ssl_prefer_server_ciphers on;

include /etc/nginx/default.d/*.conf;

location / {
try_files $uri $uri/ /index.php?$args;
}


location = /robots.txt {
allow all;
log_not_found off;
access_log off;
}

location ~ /\. {
deny all;
access_log off;
log_not_found off;
}

location ~ [^/]\.php(/|$) {
try_files $uri $uri/ /index.php?$args;
fastcgi_pass    127.0.0.1:9001;
fastcgi_index  index.php;
fastcgi_param  SCRIPT_FILENAME  $document_root$fastcgi_script_name;
include         /etc/nginx/fastcgi_params;
fastcgi_buffer_size 128k;
fastcgi_read_timeout 150;
fastcgi_buffers 256 4k;
fastcgi_busy_buffers_size 256k;
fastcgi_temp_file_write_size 256k;
}

error_page 404 /404.html;
location = /40x.html {
}

error_page 500 502 503 504 /50x.html;
location = /50x.html {
}
}
}
' > "/etc/nginx/nginx.conf"

#touch "/etc/nginx/default.d/ssl-redirection.conf"
#echo -e 'return 301 https://$host$request_uri/;' > "/etc/nginx/default.d/ssl-redirection.conf"
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
    
echo -e "
    upstream php-fpm {
        server 127.0.0.1:9000;
}
" > "/etc/nginx/conf.d/php-fpm.conf"

sed -i 's/;cgi.fix_pathinfo=1/cgi.fix_pathinfo=0/g' "/etc/php.ini"
sed -i 's/listen = \/run\/php-fpm\/www.sock/listen= 127.0.0.1:9000/g' "/etc/php-fpm.d/www.conf"
sed -i 's/user = apache/user = nginx/g' "/etc/php-fpm.d/www.conf"
sed -i 's/group = apache/group = nginx/g' "/etc/php-fpm.d/www.conf"
sed -i 's/server \/run\/php-fpm\/www.sock/server 127.0.0.1:9000/g' "/etc/nginx/conf.d/php-fpm.conf"
sed -i 's/;listen.owner = nobody/listen.owner = nginx/g' "/etc/php-fpm.d/www.conf"
sed -i 's/;listen.group = nobody/listen.group = nginx/g' "/etc/php-fpm.d/www.conf"
sed -i 's/;listen.mode = 0660/listen.mode = 0660/g' "/etc/php-fpm.d/www.conf"

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
      
  chown ${user}:${user} "$WP_WEBROOT/.htaccess"

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
    mysql_sudo -e "create database "$db_name" character set utf8 collate utf8_general_ci"
    [[ $? == 0 ]] || die "Database \`${db_name}' is not created."

    warn "Grating privileges to \`$db_user' "
    mysql_sudo -e "grant all privileges on "$db_name".* to "$db_user"@localhost identified by \"$db_pass\""
    [[ $? == 0 ]] || die "\`$db_user' privileges granted."
      
    chown ${user}:${user} $WP_WEBROOT  

    if [[ $VERSION == "son" ]];
      then
        user "cd $WP_WEBROOT &&
        wp core download --locale=en_US"
      else
        user "cd $WP_WEBROOT &&
        wp core download --version=$VERSION --locale=en_US"
      fi

    user "cd $WP_WEBROOT &&
    wp core config --dbname=$db_name --dbuser=$db_user --dbpass=$db_pass &&
    wp core install --url="http://${WP_DOMAIN}" --title=$WP_NAME --admin_user=$WP_ADMIN --admin_password=$ADMIN_PASS --admin_email=email@example.org"
      
    [[ -d "$WP_WEBROOT/wp-content/uploads" ]] || mkdir "$WP_WEBROOT/wp-content/uploads"
    chown -R nginx:nginx "$WP_WEBROOT/wp-content/uploads"
    sed -e "\$adefine('FS_METHOD', 'direct');" "$WP_WEBROOT/wp-config.php"
    echo -e "<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
RewriteRule ^index\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>"> "$WP_WEBROOT/.htaccess"
      
    chown ${user}:${user} "$WP_WEBROOT/.htaccess"
      
    user "cd $WP_WEBROOT &&
    wp user create vagrant email@example.org --role=administrator --user_pass=Kid32do${WP_NAME} --display_name='Özgür Yazılım' --first_name=Ozgur --last_name=Yazilim &&
    cd $WP_WEBROOT && wp theme activate twentyseventeen"
} 


install_webmin() {
    dnf update -y && yum install -y wget && wget https://prdownloads.sourceforge.net/webadmin/webmin-1.930-1.noarch.rpm && dnf install -y perl perl-Net-SSLeay openssl perl-Encode-Detect && rpm -ivh webmin-1.930-1.noarch.rpm
    firewall-cmd --add-port=10000/tcp --permanent && firewall-cmd --reload
}

install_postfix() {
    dnf install -y postfix && systemctl enable postfix; systemctl start postfix
}

configure_postfix() {
    echo -e "
smtpd_banner = $myhostname ESMTP
biff = no
append_dot_mydomain = no
readme_directory = no
compatibility_level = 2

# TLS parameters
smtpd_tls_cert_file = /etc/ssl/certs/postfix.pem
smtpd_tls_key_file = /etc/ssl/private/nginx-selfsigned.key
smtpd_use_tls=yes
smtpd_tls_session_cache_database = btree:${data_directory}/smtpd_scache
smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache


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
myhostname = localhost
myorigin = /etc/mailname
mynetworks_style = subnet
smtp_sasl_auth_enable = yes
smtpd_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/smtp_sasl_password_map
smtp_sasl_security_options = noanonymous" > "/etc/postfix/main.cf"

echo -e "
smtp      inet  n       -       y       -       -       smtpd
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
showq     unix  n       -       y       -       -       showq
error     unix  -       -       y       -       -       error
retry     unix  -       -       y       -       -       error
discard   unix  -       -       y       -       -       discard
local     unix  -       n       n       -       -       local
virtual   unix  -       n       n       -       -       virtual
lmtp      unix  -       -       y       -       -       lmtp
anvil     unix  -       -       y       -       1       anvil
scache    unix  -       -       y       -       1       scache
maildrop  unix  -       n       n       -       -       pipe
  flags=DRhu user=vmail argv=/usr/bin/maildrop -d ${recipient}
uucp      unix  -       n       n       -       -       pipe
  flags=Fqhu user=uucp argv=uux -r -n -z -a$sender - $nexthop!rmail ($recipient)
ifmail    unix  -       n       n       -       -       pipe
  flags=F user=ftn argv=/usr/lib/ifmail/ifmail -r $nexthop ($recipient)
bsmtp     unix  -       n       n       -       -       pipe
  flags=Fq. user=bsmtp argv=/usr/lib/bsmtp/bsmtp -t$nexthop -f$sender $recipient
scalemail-backend unix  -   n   n   -   2   pipe
  flags=R user=scalemail argv=/usr/lib/scalemail/bin/scalemail-store ${nexthop} ${user} ${extension}
mailman   unix  -       n       n       -       -       pipe
  flags=FR user=list argv=/usr/lib/mailman/bin/postfix-to-mailman.py
  ${nexthop} ${user}" > "/etc/postfix/master.cf"
}

[[ -e "${WP_CONF}" ]] || die "WP configuration file \`${WP_CONF}' is empty."
source "${WP_CONF}" || die "WP configuration file \`${WP_CONF} wrong."


if [[ -n "$WP_NAME" && -n "$VERSION" ]]; then
    prepare
    install_mariadb
    install_nginx
    configure_nginx
    install_php
    configure_phpfpm
    install_wp_cli
    check_environment
    create_wp
    create_htaccess
    install_ssl_locale
    install_webmin
    install_postfix
    configure_postfix
    echo "Wordpress installation completed."
fi
# Reload configuration
systemctl restart php-fpm >/dev/null 2>&1
systemctl reload nginx >/dev/null 2>&1
# Give some useful info
echo "Script completed."
echo "You can visit http://${DOMAIN}"
echo "You can visit webmin http://{DOMAIN}:10000"
echo "WP Admin : $WP_ADMIN / $ADMIN_PASS"
echo "Vagrant Password: Vagrant / Kid32do${WP_NAME}"

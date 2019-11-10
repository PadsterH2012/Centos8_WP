#!/usr/bin/env bash
# gelistirici:/opt/scripts/mkwp

# Configuration
WP_CONF="${WP_CONF:-/opt/scripts/wp.conf}"

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
    die "MySQL veritabanı kullanıcı bilgileri \`${WP_CONF}' dosyasına bulunamadı."
    fi

    mysql --host="$mysql_host" --port "$mysql_port" \
      --user="$WP_MYSQL_SUUSER" "$@"
}

vagrant(){
    su - vagrant -c "$@"
}

install_nginx() {
    yum install -y nginx && systemctl enable nginx && systemctl start nginx
    systemctl start firewalld && firewall-cmd --permanent --zone=public  --add-service=http && firewall-cmd --permanent --zone=public  --add-service=httpd && firewall-cmd --reload
}

install_php() {
    rpm -Uvh https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm && yum install -y https://rpms.remirepo.net/enterprise/remi-release-8.rpm && yum module enable php:remi-7.3 -y && yum install -y php php-cli php-common php-fpm php-mysqlnd php-dom php-simplexml php-ssh2 php-xml php-xmlreader php-curl php-date php-exif php-filter php-ftp php-gd php-hash php-iconv php-json php-libxml php-pecl-imagick php-mbstring php-mysqlnd php-openssl php-pcre php-posix php-sockets php-spl php-tokenizer php-zlib
}

check_environment() {
    mkdir /var/www/${DOMAIN}
    # Better safe than sorry
    [[ $EUID == 0 ]] || die "Bu betik ancak root kullanıcısı tarafından çalıştırılabilir."

    # Check configuration
    for env in WP_{ROOT,NGINX_CONFIG,PHPFPM_CONFIG} \
        WP_MYSQL_{HOST,PORT,SUUSER,SUPASS} ; do
    [[ -n "${!env}" ]] || die "Ayar ${env} wp ayar dosyası \`${WP_CONF}' içinde tanınlanmamış."
    done

    # Check MySQL username length (max length is 16)
    export WP_MYSQL_USERNAME="${WP_NAME}"
    if [[ ${#WP_MYSQL_USERNAME} -gt 16 ]]; then
    die "MySQL kullanıcı adı \`${WP_MYSQL_USERNAME}' 16 karakter sınırını aşıyor"
    fi
    export WP_MYSQL_DATABASE="${WP_NAME}"

    [[ -d "$WP_ROOT" ]] || die "WP kök dizini \'${WP_ROOT}' bir dizin değil."
    pushd "$WP_ROOT" &>/dev/null

    export WP_WEBROOT="${WP_ROOT}/${WP_NAME}"
    [[ -d "$WP_WEBROOT" ]] && die "WP hedef dizini \`${WP_WEBROOT}' var. Üzerine yazılmayacak."
      
    export WP_DOMAIN="example.org/${WP_NAME}"
}

configure_phpfpm(){
    warn "PHP-FPM pool tanımı yapılıyor..."
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

  [[ $? == 0 ]] || die "PHP-FPM ayarları yapılamadı."
}

configure_nginx() {
# If you need confire phpfpm, uncomment line below
#  configure_phpfpm
  warn "Nginx ayarları yapılıyor..." 

mkdir ${WP_NGINX_CONFIG}
touch ${WP_NGINX_CONFIG}/${WP_NAME}.conf

echo -e "\tlocation /${WP_NAME} {
\t\ttry_files \$uri \$uri/ /${WP_NAME}/index.php?\$args;
\t}" > "${WP_NGINX_CONFIG}/${WP_NAME}.conf"

  [[ $? == 0 ]] || die "Nginx ayarları yapılamadı."
}

create_htaccess() {
  warn ".htaccess oluşturuluyor..."

  echo -e "<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /${WP_NAME}/
RewriteRule ^index\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /${WP_NAME}/index.php [L]
</IfModule>"> "$WP_WEBROOT/.htaccess"
      
  chown vagrant:vagrant "$WP_WEBROOT/.htaccess"

  [[ $? == 0 ]] || die ".htaccess oluşturulamadı."
}


create_wp() {
    testlink=$(basename "${WP_UPLOADS}" .tar.gz)
    local db_name="t_$(echo "${WP_MYSQL_DATABASE}" | tr '-' '_')" 
    local db_user="t_$(echo "${WP_MYSQL_USERNAME}" | tr '-' '_')" 
    local db_pass="$(generate_password 16)"
    HTTP_PASS="$(generate_password 16)"
    ADMIN_PASS="$(generate_password 16)"

    warn "Veritabanı \`${db_name}' oluşturuluyor"
    mysql_sudo -e "create database "$db_name" character set utf8 collate utf8_turkish_ci"
    [[ $? == 0 ]] || die "Veritabanı \`${db_name}' oluşturulamadı."

    warn "\`$db_user' kullanıcısına hak tanınıyor."
    mysql_sudo -e "grant all privileges on "$db_name".* to "$db_user"@localhost identified by \"$db_pass\""
    [[ $? == 0 ]] || die "\`$db_user' kullanıcısına hak tanınamadı."
      
    mkdir $WP_WEBROOT
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
RewriteBase /${WP_NAME}/
RewriteRule ^index\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /${WP_NAME}/index.php [L]
</IfModule>"> "$WP_WEBROOT/.htaccess"
      
    chown vagrant:vagrant "$WP_WEBROOT/.htaccess"
      
    vagrant "cd $WP_WEBROOT &&
    wp user create vagrant email@example.org --role=administrator --user_pass=Kid32do${WP_NAME} --display_name='Özgür Yazılım' --first_name=Ozgur --last_name=Yazilim &&
    cd $WP_WEBROOT/wp-content/themes" 2>/dev/null
} 


update_wp_sites() {
       echo -e "${WP_WEBROOT}\t${WP_DOMAIN}" >> /opt/scripts/wp_sites.txt
}

[[ -e "${WP_CONF}" ]] || die "WP ayar dosyası \`${WP_CONF}' yok."
source "${WP_CONF}" || die "WP ayar dosyası \`${WP_CONF} hatalı."


if [[ -n "$WP_NAME" && -n "$VERSION" ]]; then
    install_nginx
    install_php
    check_environment
    create_wp
    configure_nginx
    create_htaccess
    update_wp_sites
    echo "Wordpress kurulumu tamamlandı."
fi
# Reload configuration
systemctl restart php-fpm >/dev/null 2>&1
systemctl reload nginx >/dev/null 2>&1
# Give some useful info
echo "İşlem başarıyla tamamlandı."
echo "http://${WP_DOMAIN} adresini ziyaret edebilirsiniz."
echo "Admin Kullanıcı / Parolası: admin / $ADMIN_PASS"
echo "Vagrant Kullanıcı / Parolası: Vagrant / Kid32do${WP_NAME}"

See docs in mkdocs


# install special modules

- https://github.com/trolldbois/python3-adns
- https://github.com/certator/pyping

# mount inside docker container
host:
docker run -d --ulimit nofile=65536:65536 -p 8000:8000 --name okerr3 -v /home/xenon/repo/okerr3/:/root/okerr3 jgoerzen/debian-base-minimal
docker exec -it okerr3 /bin/bash

docker:
apt update; apt install python3-pip python3-venv
python3 -m venv ~/venv/okerr3
. ~/venv/okerr3/bin/activate

./manage.py runserver 0.0.0.0:8000

docker stop okerr3
docker rm okerr3

# LXC

lxc-create -n okerr3 -t download -- --dist=debian --release=stretch --arch=amd64
mkdir /var/lib/lxc/okerr3/rootfs/opt/okerr

# Example mount
lxc.mount.entry = /home/xenon/repo/okerr3 /var/lib/lxc/okerr3/rootfs/opt/okerr none bind 0 0

# Pre-install (clean debian)
apt install python3

# Install
~~~
cd /opt/okerr
./okerr-install --fix --apache
~~~

# Post-install config
## Create admin user from server
~~~
su - okerr
./manage.py profile --create admin@example.com --pass adminpass
./manage.py group --assign Admin --user admin@example.com --infinite
~~~

# Install dehydrated (ONLY PRIVATE, SORRY)
~~~
apt install dehydrated
pip3 dns-lexicon probably
pip uninstall pyOpenSSL
/usr/bin/dehydrated --register --accept-terms
echo "example.okerr.com cat.okerr.com" >
./dehydrated-renew.sh
~~~

if `AttributeError: module 'lib' has no attribute 'X509_up_ref'` happens:
~~~
sudo python3 -m easy_install --upgrade pyOpenSSL
~~~
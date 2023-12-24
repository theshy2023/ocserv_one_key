version_check(){
	version=`cat /etc/debian_version`
	tmp=${version: 0: 1}
	if [ "$tmp" -gt "1" ];then
		echo $version
		echo 'only support debian_version >= 10'
		exit
	fi
}

install_ocserv(){
	apt update -y
	apt upgrade -y
	apt install iptables -y
	apt install ocserv -y
}

edit_conf(){
	echo -n "Server Address " > /etc/ocserv/server.address
	echo -n $1 >> /etc/ocserv/server.address
	echo ":3389(Port MUST Not Blocked)" >> /etc/ocserv/server.address
	curl -o /etc/ocserv/ocserv.conf https://raw.githubusercontent.com/theshy2023/ocserv_one_key/main/ocserv.conf 
}

edit_iptables(){
	echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
	echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
	echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
	sysctl -p
	iptables -t nat -A POSTROUTING -s 192.168.1.0/24 -o eth0 -j MASQUERADE
	iptables -A FORWARD -s 192.168.1.0/24 -j ACCEPT
}

do_mkcert(){
	rm -f mkcert-v*-linux-amd64
	curl -JLO "https://dl.filippo.io/mkcert/latest?for=linux/amd64"
	chmod +x mkcert-v*-linux-amd64
	sudo cp mkcert-v*-linux-amd64 /usr/local/bin/mkcert
	mkcert -key-file /etc/ocserv/private.key -cert-file /etc/ocserv/public.crt $1
}

create_ca(){
	rm -rf $1
	mkdir $1
	apt install gnutls-bin
	curl -o $1/ca-cert.cfg https://raw.githubusercontent.com/theshy2023/ocserv_one_key/main/ca-cert.cfg
	curl -o $1/client-cert.cfg https://raw.githubusercontent.com/theshy2023/ocserv_one_key/main/client-cert.cfg
	certtool --generate-privkey --outfile $1/ca-privkey.pem
	certtool --generate-self-signed --load-privkey $1/ca-privkey.pem --template $1/ca-cert.cfg --outfile $1/ca-cert.pem
	certtool --generate-privkey --outfile $1/client-privkey.pem
	certtool --generate-certificate --load-privkey $1/client-privkey.pem --load-ca-certificate $1/ca-cert.pem --load-ca-privkey $1/ca-privkey.pem --template $1/client-cert.cfg --outfile $1/client-cert.pem	
}

create_client_p12(){
	certtool --to-p12 --load-privkey $1/client-privkey.pem --load-certificate $1/client-cert.pem --pkcs-cipher 3des-pkcs12 --outfile $1/client.p12 --outder
}

version_check
ssl_dir=/etc/ocserv/ssl_dir
public_ip=`curl ipv4.icanhazip.com`
echo "Your Ipv4:"
echo -e "\e[31m$public_ip\e[0m"
install_ocserv
do_mkcert $public_ip
create_ca $ssl_dir
create_client_p12 $ssl_dir
edit_conf
edit_iptables
systemctl restart ocserv
systemctl status ocserv


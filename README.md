# scanweb
Script that runs through typical attempts to discover directories and files using typical techniques - all done in one script

## summary

This script is more for my own benefit than created for anyone else, but others may find use for it.

I found myself repeating the same sorts of scans every time I was attempting a new box in hackthebox or similar.
This script runs through the typical scans for files and directories in webhosts that are done on new boxes and puts results in to output files.
The dictionaries used and the techniques used are those that I found consistently revealed what was needed on every box I've done so far. If I come across
one that isn't found using these techniques, I'll change the script so that it does work next time.

It uses ffuf and gobuster for the various techniques

gobuster for vhost scanning (I like it for that)

ffuf for all the rest (I tried several tools and techniques but personally like this one the best)

Dictionaries are all from SecLists - https://github.com/danielmiessler/SecLists

## usage examples:

    # usage syntax
    # ./scanweb.sh -i <ip-address> --host <hostname> --usehost <use-hostname-instead-of-ip> -e <file-extensions> --usehttps <is-https> -t <num-threads> 
    --outdir <output-file-dir> [-d <sub-dir>] [--customsecpath <custom-seclists-path>] [--port <custom-port>] 
    [--proxyurl <proxy-url> (For example: http://127.0.0.1:8080 or socks5://127.0.0.1:8080)] [--replayproxyurl <replay-proxy-url>]

My typical runs:

    # first scan (use the appropriate language - this example is php but could be aspx instead for example)
    # note - this also does vhost scanning (only does that when you search by IP address):
    ./scanweb.sh -i <ip> --host <host>.htb --usehost n -e .php,.html,.txt --usehttps n -t 200 --outdir ./results
    
    # if find vhosts from above, then also try scanning those after:
    ./scanweb.sh -i <ip> --host myvhost.<host>.htb --usehost y -e .php,.html,.txt --usehttps n -t 200 --outdir ./results
    
    # if find subdir that you want to scan:
    ./scanweb.sh -i <ip> --host <host>.htb --usehost n -e .php,.html,.txt --usehttps n -t 200 -d mysubdir --outdir ./results


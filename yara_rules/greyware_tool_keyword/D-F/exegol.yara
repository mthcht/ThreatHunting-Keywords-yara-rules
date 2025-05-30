rule exegol
{
    meta:
        description = "Detection patterns for the tool 'exegol' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "exegol"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string1 = /\s\-f\s.{0,1000}\.dmp\swindows\.cmdline/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string2 = /\s\-f\s.{0,1000}\.dmp\swindows\.dlllist\s\-\-pid\s/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string3 = /\s\-f\s.{0,1000}\.dmp\swindows\.filescan/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string4 = /\s\-f\s.{0,1000}\.dmp\swindows\.handles\s\-\-pid\s/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string5 = /\s\-f\s.{0,1000}\.dmp\swindows\.info/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string6 = /\s\-f\s.{0,1000}\.dmp\swindows\.malfind/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string7 = /\s\-f\s.{0,1000}\.dmp\swindows\.netscan/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string8 = /\s\-f\s.{0,1000}\.dmp\swindows\.netstat/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string9 = /\s\-f\s.{0,1000}\.dmp\swindows\.pslist/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string10 = /\s\-f\s.{0,1000}\.dmp\swindows\.psscan/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string11 = /\s\-f\s.{0,1000}\.dmp\swindows\.pstree/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string12 = /\s\-f\s.{0,1000}\.dmp\swindows\.registry\.hivelist/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string13 = /\s\-f\s.{0,1000}\.dmp\swindows\.registry\.hivescan/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string14 = /\s\-f\s.{0,1000}\.dmp\swindows\.registry\.printkey/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string15 = /\s\-f\s.{0,1000}\.dmp\swindows\.registry\.printkey.{0,1000}Software\\Microsoft\\Windows\\CurrentVersion/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string16 = /\shttp\-put\-server\.py/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string17 = /\/http\-put\-server\.py/
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string18 = /dig\saxfr\s.{0,1000}\s\@/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string19 = /ftp\-server\s\-u\s.{0,1000}\s\-P\s.{0,1000}\s\-p\s2121/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string20 = /nbtscan\s\-r\s.{0,1000}\/24/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string21 = "net rpc group addmem 'Domain admins' " nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string22 = "net rpc group members 'Domain admins' -U " nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string23 = /netdiscover\s\-i\s.{0,1000}\s\-r\s.{0,1000}\/24/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string24 = /ngrok\sauthtoken\sAUTHTOKEN\:\:\:https\:\/\/dashboard\.ngrok\.com\/get\-started\/your\-authtoken/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string25 = "nmap -Pn -v -sS -F" nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string26 = /pwnedornot\.py\s\-d\s/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string27 = "scout aws --profile default -f" nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string28 = "scout azure --cli" nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string29 = "screen /dev/ttyACM0 115200" nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string30 = "snmpwalk -c public -v 1 " nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string31 = "snmpwalk -c public -v 2c " nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string32 = /tailscale\sup\s\-\-advertise\-routes\=.{0,1000}\/24/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string33 = "tailscaled --tun=userspace-networking --socks5-server=" nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string34 = "volatility2 --profile=" nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string35 = /volatility3\s\-f\s.{0,1000}\.dmp/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string36 = "vulny-code-static-analysis --dir " nocase ascii wide

    condition:
        any of them
}

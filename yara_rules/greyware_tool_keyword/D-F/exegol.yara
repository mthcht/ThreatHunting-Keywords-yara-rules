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
        $string1 = /.{0,1000}\s\-f\s.{0,1000}\.dmp\swindows\.cmdline.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string2 = /.{0,1000}\s\-f\s.{0,1000}\.dmp\swindows\.dlllist\s\-\-pid\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string3 = /.{0,1000}\s\-f\s.{0,1000}\.dmp\swindows\.filescan.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string4 = /.{0,1000}\s\-f\s.{0,1000}\.dmp\swindows\.handles\s\-\-pid\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string5 = /.{0,1000}\s\-f\s.{0,1000}\.dmp\swindows\.info.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string6 = /.{0,1000}\s\-f\s.{0,1000}\.dmp\swindows\.malfind.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string7 = /.{0,1000}\s\-f\s.{0,1000}\.dmp\swindows\.netscan.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string8 = /.{0,1000}\s\-f\s.{0,1000}\.dmp\swindows\.netstat.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string9 = /.{0,1000}\s\-f\s.{0,1000}\.dmp\swindows\.pslist.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string10 = /.{0,1000}\s\-f\s.{0,1000}\.dmp\swindows\.psscan.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string11 = /.{0,1000}\s\-f\s.{0,1000}\.dmp\swindows\.pstree.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string12 = /.{0,1000}\s\-f\s.{0,1000}\.dmp\swindows\.registry\.hivelist.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string13 = /.{0,1000}\s\-f\s.{0,1000}\.dmp\swindows\.registry\.hivescan.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string14 = /.{0,1000}\s\-f\s.{0,1000}\.dmp\swindows\.registry\.printkey.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string15 = /.{0,1000}\s\-f\s.{0,1000}\.dmp\swindows\.registry\.printkey.{0,1000}Software\\Microsoft\\Windows\\CurrentVersion.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string16 = /.{0,1000}\shttp\-put\-server\.py.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string17 = /.{0,1000}\/http\-put\-server\.py.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string18 = /.{0,1000}dig\saxfr\s.{0,1000}\s\@.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string19 = /.{0,1000}ftp\-server\s\-u\s.{0,1000}\s\-P\s.{0,1000}\s\-p\s2121.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string20 = /.{0,1000}nbtscan\s\-r\s.{0,1000}\/24.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string21 = /.{0,1000}net\srpc\sgroup\saddmem\s\'Domain\sadmins\'\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string22 = /.{0,1000}net\srpc\sgroup\smembers\s\'Domain\sadmins\'\s\-U\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string23 = /.{0,1000}netdiscover\s\-i\s.{0,1000}\s\-r\s.{0,1000}\/24.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string24 = /.{0,1000}ngrok\sauthtoken\sAUTHTOKEN:::https:\/\/dashboard\.ngrok\.com\/get\-started\/your\-authtoken.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string25 = /.{0,1000}nmap\s\-Pn\s\-v\s\-sS\s\-F.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string26 = /.{0,1000}pwnedornot\.py\s\-d\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string27 = /.{0,1000}scout\saws\s\-\-profile\sdefault\s\-f.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string28 = /.{0,1000}scout\sazure\s\-\-cli.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string29 = /.{0,1000}screen\s\/dev\/ttyACM0\s115200.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string30 = /.{0,1000}snmpwalk\s\-c\spublic\s\-v\s1\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string31 = /.{0,1000}snmpwalk\s\-c\spublic\s\-v\s2c\s.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string32 = /.{0,1000}tailscale\sup\s\-\-advertise\-routes\=.{0,1000}\/24.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string33 = /.{0,1000}tailscaled\s\-\-tun\=userspace\-networking\s\-\-socks5\-server\=.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string34 = /.{0,1000}volatility2\s\-\-profile\=.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string35 = /.{0,1000}volatility3\s\-f\s.{0,1000}\.dmp.{0,1000}/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string36 = /.{0,1000}vulny\-code\-static\-analysis\s\-\-dir\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}

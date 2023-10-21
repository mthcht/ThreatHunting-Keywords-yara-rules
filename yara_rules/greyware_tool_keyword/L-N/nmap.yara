rule nmap
{
    meta:
        description = "Detection patterns for the tool 'nmap' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nmap"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: A very common tool. Network host vuln and port detector.
        // Reference: https://github.com/nmap/nmap
        $string1 = /\.\/nmap/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string2 = /\.\/test\/nmap.*\/.*\.nse/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string3 = /\/nmap\-nse\-scripts/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string4 = /\/nmap\-scada/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string5 = /\/nmap\-vulners/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string6 = /\/nse_install\// nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string7 = /\/nse\-install\.git/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string8 = /\/s4n7h0\/NSE/ nocase ascii wide
        // Description: When Nmap is used on Windows systems. it can perform various types of scans such as TCP SYN scans. UDP scans. and service/version detection. These scans enable the identification of open ports. services running on those ports. and potential vulnerabilities in target systems.
        // Reference: N/A
        $string9 = /\\nmap\.exe.*\/24/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string10 = /b4ldr\/nse\-scripts/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string11 = /external\-nse\-script\-library/ nocase ascii wide
        // Description: Nmap Scan Every Interface that is Assigned an IP address
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string12 = /ifconfig\s\-a\s\|\sgrep\s.*\s\|\sxargs\snmap\s\-/ nocase ascii wide
        // Description: A very common tool. Network host vuln and port detector.
        // Reference: https://github.com/nmap/nmap
        $string13 = /nmap\s\-/ nocase ascii wide
        // Description: check exploit for CVEs with nmap
        // Reference: https://nmap.org/
        $string14 = /nmap\s.*\s\-\-script\=.*\.nse/ nocase ascii wide
        // Description: When Nmap is used on Windows systems. it can perform various types of scans such as TCP SYN scans. UDP scans. and service/version detection. These scans enable the identification of open ports. services running on those ports. and potential vulnerabilities in target systems.
        // Reference: N/A
        $string15 = /nmap\-.*\-setup\.exe/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string16 = /nmap\-elasticsearch\-nse/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string17 = /nse_install\.py/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string18 = /nse\-insall\-0\.0\.1/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string19 = /nse\-install\s/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string20 = /nse\-install\-master/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string21 = /OCSAF\/freevulnsearch/ nocase ascii wide
        // Description: Nmap Privilege Escalation
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string22 = /os\.execute\(.*\/bin\/.*nmap\s\-\-script\=\$/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string23 = /psc4re\/NSE\-scripts/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string24 = /remiflavien1\/nse\-install/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string25 = /shadawck\/nse\-install/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string26 = /takeshixx\/nmap\-scripts/ nocase ascii wide
        // Description: When Nmap is used on Windows systems. it can perform various types of scans such as TCP SYN scans. UDP scans. and service/version detection. These scans enable the identification of open ports. services running on those ports. and potential vulnerabilities in target systems.
        // Reference: N/A
        $string27 = /zenmap\.exe/ nocase ascii wide
        // Description: ZMap is a fast single packet network scanner designed for Internet-wide network surveys. On a typical desktop computer with a gigabit Ethernet connection. ZMap is capable scanning the entire public IPv4 address space in under 45 minutes. With a 10gigE connection and PF_RING. ZMap can scan the IPv4 address space in under 5 minutes. ZMap operates on GNU/Linux. Mac OS. and BSD. ZMap currently has fully implemented probe modules for TCP SYN scans. ICMP. DNS queries. UPnP. BACNET. and can send a large number of UDP probes. If you are looking to do more involved scans. e.g.. banner grab or TLS handshake. take a look at ZGrab. ZMaps sister project that performs stateful application-layer handshakes.
        // Reference: https://github.com/zmap/zmap
        $string28 = /zmap\s\-/ nocase ascii wide
        // Description: A very common tool. Network host vuln and port detector.
        // Reference: https://github.com/nmap/nmap
        $string29 = /nmap\s/ nocase ascii wide

    condition:
        any of them
}
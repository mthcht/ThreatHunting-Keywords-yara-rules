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
        $string2 = /\.\/test\/nmap.{0,1000}\/.{0,1000}\.nse/ nocase ascii wide
        // Description: Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/nmap/nmap/blob/635675b1430a89e950f71112d3bfc74feee4b19a/nselib/http.lua#L2600
        $string3 = /\/Nmap\/folder\/check15/ nocase ascii wide
        // Description: Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/nmap/nmap/blob/635675b1430a89e950f71112d3bfc74feee4b19a/nselib/http.lua#L2600
        $string4 = /\/Nmap\/folder\/check16/ nocase ascii wide
        // Description: Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/nmap/nmap/blob/635675b1430a89e950f71112d3bfc74feee4b19a/nselib/http.lua#L2600
        $string5 = /\/Nmap\/folder\/check17/ nocase ascii wide
        // Description: Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing
        // Reference: https://nmap.org/book/nse-usage.html
        $string6 = /\/nmaplowercheck15/ nocase ascii wide
        // Description: Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/nmap/nmap/blob/635675b1430a89e950f71112d3bfc74feee4b19a/nselib/http.lua#L2600
        $string7 = /\/nmaplowercheck16/ nocase ascii wide
        // Description: Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/nmap/nmap/blob/635675b1430a89e950f71112d3bfc74feee4b19a/nselib/http.lua#L2600
        $string8 = /\/nmaplowercheck17/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string9 = /\/nmap\-nse\-scripts/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string10 = /\/nmap\-scada/ nocase ascii wide
        // Description: Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/nmap/nmap/blob/635675b1430a89e950f71112d3bfc74feee4b19a/nselib/http.lua#L2600
        $string11 = /\/NmapUpperCheck15/ nocase ascii wide
        // Description: Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/nmap/nmap/blob/635675b1430a89e950f71112d3bfc74feee4b19a/nselib/http.lua#L2600
        $string12 = /\/NmapUpperCheck16/ nocase ascii wide
        // Description: Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/nmap/nmap/blob/635675b1430a89e950f71112d3bfc74feee4b19a/nselib/http.lua#L2600
        $string13 = /\/NmapUpperCheck17/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string14 = /\/nmap\-vulners/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string15 = /\/nse_install\// nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string16 = /\/nse\-install\.git/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string17 = /\/s4n7h0\/NSE/ nocase ascii wide
        // Description: When Nmap is used on Windows systems. it can perform various types of scans such as TCP SYN scans. UDP scans. and service/version detection. These scans enable the identification of open ports. services running on those ports. and potential vulnerabilities in target systems.
        // Reference: N/A
        $string18 = /\\nmap\.exe.{0,1000}\/24/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string19 = /b4ldr\/nse\-scripts/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string20 = /external\-nse\-script\-library/ nocase ascii wide
        // Description: Nmap Scan Every Interface that is Assigned an IP address
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string21 = /ifconfig\s\-a\s\|\sgrep\s.{0,1000}\s\|\sxargs\snmap\s\-/ nocase ascii wide
        // Description: A very common tool. Network host vuln and port detector.
        // Reference: https://github.com/nmap/nmap
        $string22 = /nmap\s\-/ nocase ascii wide
        // Description: check exploit for CVEs with nmap
        // Reference: https://nmap.org/
        $string23 = /nmap\s.{0,1000}\s\-\-script\=.{0,1000}\.nse/ nocase ascii wide
        // Description: SMB lateral movement with nmap
        // Reference: N/A
        $string24 = /nmap\s\-p\s445\s.{0,1000}\s\-sS\s\-\-script\ssmb\-security\-mode/ nocase ascii wide
        // Description: When Nmap is used on Windows systems. it can perform various types of scans such as TCP SYN scans. UDP scans. and service/version detection. These scans enable the identification of open ports. services running on those ports. and potential vulnerabilities in target systems.
        // Reference: N/A
        $string25 = /nmap\-.{0,1000}\-setup\.exe/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string26 = /nmap\-elasticsearch\-nse/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string27 = /nse_install\.py/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string28 = /nse\-insall\-0\.0\.1/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string29 = /nse\-install\s/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string30 = /nse\-install\-master/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string31 = /OCSAF\/freevulnsearch/ nocase ascii wide
        // Description: Nmap Privilege Escalation
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string32 = /os\.execute\(.{0,1000}\/bin\/.{0,1000}nmap\s\-\-script\=\$/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string33 = /psc4re\/NSE\-scripts/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string34 = /remiflavien1\/nse\-install/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string35 = /shadawck\/nse\-install/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string36 = /takeshixx\/nmap\-scripts/ nocase ascii wide
        // Description: When Nmap is used on Windows systems. it can perform various types of scans such as TCP SYN scans. UDP scans. and service/version detection. These scans enable the identification of open ports. services running on those ports. and potential vulnerabilities in target systems.
        // Reference: N/A
        $string37 = /zenmap\.exe/ nocase ascii wide
        // Description: ZMap is a fast single packet network scanner designed for Internet-wide network surveys. On a typical desktop computer with a gigabit Ethernet connection. ZMap is capable scanning the entire public IPv4 address space in under 45 minutes. With a 10gigE connection and PF_RING. ZMap can scan the IPv4 address space in under 5 minutes. ZMap operates on GNU/Linux. Mac OS. and BSD. ZMap currently has fully implemented probe modules for TCP SYN scans. ICMP. DNS queries. UPnP. BACNET. and can send a large number of UDP probes. If you are looking to do more involved scans. e.g.. banner grab or TLS handshake. take a look at ZGrab. ZMaps sister project that performs stateful application-layer handshakes.
        // Reference: https://github.com/zmap/zmap
        $string38 = /zmap\s\-/ nocase ascii wide
        // Description: A very common tool. Network host vuln and port detector.
        // Reference: https://github.com/nmap/nmap
        $string39 = /nmap\s/ nocase ascii wide

    condition:
        any of them
}

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
        $string1 = /.{0,1000}\.\/nmap.{0,1000}/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string2 = /.{0,1000}\.\/test\/nmap.{0,1000}\/.{0,1000}\.nse.{0,1000}/ nocase ascii wide
        // Description: Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/nmap/nmap/blob/635675b1430a89e950f71112d3bfc74feee4b19a/nselib/http.lua#L2600
        $string3 = /.{0,1000}\/Nmap\/folder\/check15.{0,1000}/ nocase ascii wide
        // Description: Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/nmap/nmap/blob/635675b1430a89e950f71112d3bfc74feee4b19a/nselib/http.lua#L2600
        $string4 = /.{0,1000}\/Nmap\/folder\/check16.{0,1000}/ nocase ascii wide
        // Description: Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/nmap/nmap/blob/635675b1430a89e950f71112d3bfc74feee4b19a/nselib/http.lua#L2600
        $string5 = /.{0,1000}\/Nmap\/folder\/check17.{0,1000}/ nocase ascii wide
        // Description: Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing
        // Reference: https://nmap.org/book/nse-usage.html
        $string6 = /.{0,1000}\/nmaplowercheck15.{0,1000}/ nocase ascii wide
        // Description: Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/nmap/nmap/blob/635675b1430a89e950f71112d3bfc74feee4b19a/nselib/http.lua#L2600
        $string7 = /.{0,1000}\/nmaplowercheck16.{0,1000}/ nocase ascii wide
        // Description: Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/nmap/nmap/blob/635675b1430a89e950f71112d3bfc74feee4b19a/nselib/http.lua#L2600
        $string8 = /.{0,1000}\/nmaplowercheck17.{0,1000}/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string9 = /.{0,1000}\/nmap\-nse\-scripts.{0,1000}/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string10 = /.{0,1000}\/nmap\-scada.{0,1000}/ nocase ascii wide
        // Description: Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/nmap/nmap/blob/635675b1430a89e950f71112d3bfc74feee4b19a/nselib/http.lua#L2600
        $string11 = /.{0,1000}\/NmapUpperCheck15.{0,1000}/ nocase ascii wide
        // Description: Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/nmap/nmap/blob/635675b1430a89e950f71112d3bfc74feee4b19a/nselib/http.lua#L2600
        $string12 = /.{0,1000}\/NmapUpperCheck16.{0,1000}/ nocase ascii wide
        // Description: Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/nmap/nmap/blob/635675b1430a89e950f71112d3bfc74feee4b19a/nselib/http.lua#L2600
        $string13 = /.{0,1000}\/NmapUpperCheck17.{0,1000}/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string14 = /.{0,1000}\/nmap\-vulners.{0,1000}/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string15 = /.{0,1000}\/nse_install\/.{0,1000}/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string16 = /.{0,1000}\/nse\-install\.git.{0,1000}/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string17 = /.{0,1000}\/s4n7h0\/NSE.{0,1000}/ nocase ascii wide
        // Description: When Nmap is used on Windows systems. it can perform various types of scans such as TCP SYN scans. UDP scans. and service/version detection. These scans enable the identification of open ports. services running on those ports. and potential vulnerabilities in target systems.
        // Reference: N/A
        $string18 = /.{0,1000}\\nmap\.exe.{0,1000}\/24.{0,1000}/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string19 = /.{0,1000}b4ldr\/nse\-scripts.{0,1000}/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string20 = /.{0,1000}external\-nse\-script\-library.{0,1000}/ nocase ascii wide
        // Description: Nmap Scan Every Interface that is Assigned an IP address
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string21 = /.{0,1000}ifconfig\s\-a\s\|\sgrep\s.{0,1000}\s\|\sxargs\snmap\s\-.{0,1000}/ nocase ascii wide
        // Description: A very common tool. Network host vuln and port detector.
        // Reference: https://github.com/nmap/nmap
        $string22 = /.{0,1000}nmap\s\-.{0,1000}/ nocase ascii wide
        // Description: check exploit for CVEs with nmap
        // Reference: https://nmap.org/
        $string23 = /.{0,1000}nmap\s.{0,1000}\s\-\-script\=.{0,1000}\.nse.{0,1000}/ nocase ascii wide
        // Description: When Nmap is used on Windows systems. it can perform various types of scans such as TCP SYN scans. UDP scans. and service/version detection. These scans enable the identification of open ports. services running on those ports. and potential vulnerabilities in target systems.
        // Reference: N/A
        $string24 = /.{0,1000}nmap\-.{0,1000}\-setup\.exe.{0,1000}/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string25 = /.{0,1000}nmap\-elasticsearch\-nse.{0,1000}/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string26 = /.{0,1000}nse_install\.py.{0,1000}/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string27 = /.{0,1000}nse\-insall\-0\.0\.1.{0,1000}/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string28 = /.{0,1000}nse\-install\s.{0,1000}/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string29 = /.{0,1000}nse\-install\-master.{0,1000}/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string30 = /.{0,1000}OCSAF\/freevulnsearch.{0,1000}/ nocase ascii wide
        // Description: Nmap Privilege Escalation
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string31 = /.{0,1000}os\.execute\(.{0,1000}\/bin\/.{0,1000}nmap\s\-\-script\=\$.{0,1000}/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string32 = /.{0,1000}psc4re\/NSE\-scripts.{0,1000}/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string33 = /.{0,1000}remiflavien1\/nse\-install.{0,1000}/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string34 = /.{0,1000}shadawck\/nse\-install.{0,1000}/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string35 = /.{0,1000}takeshixx\/nmap\-scripts.{0,1000}/ nocase ascii wide
        // Description: When Nmap is used on Windows systems. it can perform various types of scans such as TCP SYN scans. UDP scans. and service/version detection. These scans enable the identification of open ports. services running on those ports. and potential vulnerabilities in target systems.
        // Reference: N/A
        $string36 = /.{0,1000}zenmap\.exe.{0,1000}/ nocase ascii wide
        // Description: ZMap is a fast single packet network scanner designed for Internet-wide network surveys. On a typical desktop computer with a gigabit Ethernet connection. ZMap is capable scanning the entire public IPv4 address space in under 45 minutes. With a 10gigE connection and PF_RING. ZMap can scan the IPv4 address space in under 5 minutes. ZMap operates on GNU/Linux. Mac OS. and BSD. ZMap currently has fully implemented probe modules for TCP SYN scans. ICMP. DNS queries. UPnP. BACNET. and can send a large number of UDP probes. If you are looking to do more involved scans. e.g.. banner grab or TLS handshake. take a look at ZGrab. ZMaps sister project that performs stateful application-layer handshakes.
        // Reference: https://github.com/zmap/zmap
        $string37 = /.{0,1000}zmap\s\-.{0,1000}/ nocase ascii wide
        // Description: A very common tool. Network host vuln and port detector.
        // Reference: https://github.com/nmap/nmap
        $string38 = /nmap\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}

rule dns2tcp
{
    meta:
        description = "Detection patterns for the tool 'dns2tcp' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dns2tcp"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string1 = /.{0,1000}\.dns2tcpdrc.{0,1000}/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string2 = /.{0,1000}\/\.dns2tcprc.{0,1000}/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string3 = /.{0,1000}\/debian\/dns2tcp.{0,1000}/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string4 = /.{0,1000}\/dns2tcp\.git.{0,1000}/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string5 = /.{0,1000}\/dns2tcp\/client\/.{0,1000}/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string6 = /.{0,1000}\/dns2tcp\/common\/.{0,1000}/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string7 = /.{0,1000}\/dns2tcp\/server.{0,1000}/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string8 = /.{0,1000}\/root\/dns2tcp.{0,1000}/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string9 = /.{0,1000}\\\\\.\\pipe\\win\-sux\-no\-async\-anon\-pipe\-.{0,1000}\-.{0,1000}/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string10 = /.{0,1000}\\dns2tcp\\.{0,1000}/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string11 = /.{0,1000}\\dns2tcp\\server.{0,1000}/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string12 = /.{0,1000}\\dns2tcp\-0\..{0,1000}/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string13 = /.{0,1000}alex\-sector\/dns2tcp.{0,1000}/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string14 = /.{0,1000}apt\sinstall\sdns2tcp.{0,1000}/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string15 = /.{0,1000}dns2tcp\-.{0,1000}\.zip.{0,1000}/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string16 = /.{0,1000}dns2tcp\.exe.{0,1000}/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string17 = /.{0,1000}dns2tcp\.hsc\.fr.{0,1000}/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string18 = /.{0,1000}dns2tcp\.kali\.org.{0,1000}/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string19 = /.{0,1000}dns2tcp\.pid.{0,1000}/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string20 = /.{0,1000}dns2tcpc\s\-z\s.{0,1000}/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string21 = /.{0,1000}dns2tcpc\.exe.{0,1000}/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string22 = /.{0,1000}dns2tcpd\s\-\-.{0,1000}/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string23 = /.{0,1000}dns2tcpd\s\-f\s.{0,1000}/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string24 = /.{0,1000}dns2tcp\-master.{0,1000}/ nocase ascii wide

    condition:
        any of them
}

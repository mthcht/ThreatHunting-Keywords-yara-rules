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
        $string1 = /\.dns2tcpdrc/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string2 = /\/\.dns2tcprc/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string3 = /\/debian\/dns2tcp/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string4 = /\/dns2tcp\.git/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string5 = /\/dns2tcp\/client\// nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string6 = /\/dns2tcp\/common\// nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string7 = /\/dns2tcp\/server/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string8 = /\/root\/dns2tcp/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string9 = /\\\\\.\\pipe\\win\-sux\-no\-async\-anon\-pipe\-.{0,1000}\-/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string10 = /\\dns2tcp\\/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string11 = /\\dns2tcp\\server/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string12 = /\\dns2tcp\-0\./ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string13 = /alex\-sector\/dns2tcp/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string14 = /apt\sinstall\sdns2tcp/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string15 = /dns2tcp\-.{0,1000}\.zip/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string16 = /dns2tcp\.exe/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string17 = /dns2tcp\.hsc\.fr/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string18 = /dns2tcp\.kali\.org/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string19 = /dns2tcp\.pid/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string20 = /dns2tcpc\s\-z\s/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string21 = /dns2tcpc\.exe/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string22 = /dns2tcpd\s\-\-/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string23 = /dns2tcpd\s\-f\s/ nocase ascii wide
        // Description: Dns2tcp is a tool for relaying TCP connections over DNS
        // Reference: https://github.com/alex-sector/dns2tcp
        $string24 = /dns2tcp\-master/ nocase ascii wide

    condition:
        any of them
}

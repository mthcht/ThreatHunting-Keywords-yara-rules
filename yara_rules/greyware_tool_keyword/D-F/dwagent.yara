rule dwagent
{
    meta:
        description = "Detection patterns for the tool 'dwagent' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dwagent"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: The DWService to remotly control your machine - abused by attackers
        // Reference: https://github.com/dwservice/agent
        $string1 = /\/dwagent\.desktop/ nocase ascii wide
        // Description: The DWService to remotly control your machine - abused by attackers
        // Reference: https://github.com/dwservice/agent
        $string2 = /\/dwagent\.service/ nocase ascii wide
        // Description: The DWService to remotly control your machine - abused by attackers
        // Reference: https://github.com/dwservice/agent
        $string3 = /\/dwagsystray/ nocase ascii wide
        // Description: The DWService to remotly control your machine - abused by attackers
        // Reference: https://github.com/dwservice/agent
        $string4 = /\\\.dwagent\\/ nocase ascii wide
        // Description: The DWService to remotly control your machine - abused by attackers
        // Reference: https://github.com/dwservice/agent
        $string5 = /\\AppData\\Local\\Temp\\dwagent/ nocase ascii wide
        // Description: The DWService to remotly control your machine - abused by attackers
        // Reference: https://github.com/dwservice/agent
        $string6 = /\\CurrentVersion\\Run\\DWAgentMon/ nocase ascii wide
        // Description: The DWService to remotly control your machine - abused by attackers
        // Reference: https://github.com/dwservice/agent
        $string7 = /\\dwagent\.exe/ nocase ascii wide
        // Description: The DWService to remotly control your machine - abused by attackers
        // Reference: https://github.com/dwservice/agent
        $string8 = /\\DWAgent\.lnk/ nocase ascii wide
        // Description: The DWService to remotly control your machine - abused by attackers
        // Reference: https://github.com/dwservice/agent
        $string9 = /\\dwagent\.log/ nocase ascii wide
        // Description: The DWService to remotly control your machine - abused by attackers
        // Reference: https://github.com/dwservice/agent
        $string10 = /\\dwagent\.pid/ nocase ascii wide
        // Description: The DWService to remotly control your machine - abused by attackers
        // Reference: https://github.com/dwservice/agent
        $string11 = /\\dwagent\.start/ nocase ascii wide
        // Description: The DWService to remotly control your machine - abused by attackers
        // Reference: https://github.com/dwservice/agent
        $string12 = /\\dwagent\.stop/ nocase ascii wide
        // Description: The DWService to remotly control your machine - abused by attackers
        // Reference: https://github.com/dwservice/agent
        $string13 = /\\dwaggdi\.dll/ nocase ascii wide
        // Description: The DWService to remotly control your machine - abused by attackers
        // Reference: https://github.com/dwservice/agent
        $string14 = /\\dwaginstall\.log/ nocase ascii wide
        // Description: The DWService to remotly control your machine - abused by attackers
        // Reference: https://github.com/dwservice/agent
        $string15 = /\\dwaglnc\.exe/ nocase ascii wide
        // Description: The DWService to remotly control your machine - abused by attackers
        // Reference: https://github.com/dwservice/agent
        $string16 = /\\dwagsvc\.exe/ nocase ascii wide
        // Description: The DWService to remotly control your machine - abused by attackers
        // Reference: https://github.com/dwservice/agent
        $string17 = /\\dwagupd\.dll/ nocase ascii wide
        // Description: The DWService to remotly control your machine - abused by attackers
        // Reference: https://github.com/dwservice/agent
        $string18 = /\\Services\\DWAgent/ nocase ascii wide
        // Description: The DWService to remotly control your machine - abused by attackers
        // Reference: https://github.com/dwservice/agent
        $string19 = /\\Start\sMenu\\Programs\\DWAgent/ nocase ascii wide
        // Description: The DWService to remotly control your machine - abused by attackers
        // Reference: https://github.com/dwservice/agent
        $string20 = /\>DWAgent\</ nocase ascii wide
        // Description: The DWService to remotly control your machine - abused by attackers
        // Reference: https://github.com/dwservice/agent
        $string21 = /015774ac49fa929ca39c0707aa8177e4605b7df9f53d8630fea1ef5155bb5328/ nocase ascii wide
        // Description: The DWService to remotly control your machine - abused by attackers
        // Reference: https://github.com/dwservice/agent
        $string22 = /1429e62855ce5572b735fe0460ffa6a8f26d56199a8e166152252c7bd659d275/ nocase ascii wide
        // Description: The DWService to remotly control your machine - abused by attackers
        // Reference: https://github.com/dwservice/agent
        $string23 = /3241d780f32a6a89d3b3f30d85f21f33f9d4d91227d129b2fd81d75baa870337/ nocase ascii wide
        // Description: The DWService to remotly control your machine - abused by attackers
        // Reference: https://github.com/dwservice/agent
        $string24 = /36a7532a957652a55dbf0b196905652a1f0b8c4019b7ca4e749fa81e5f2c149b/ nocase ascii wide
        // Description: The DWService to remotly control your machine - abused by attackers
        // Reference: https://github.com/dwservice/agent
        $string25 = /4f21a1d0e7caa97018e4d0b8c7e63fbc54d081976dfda9409f57a3ead24074a7/ nocase ascii wide
        // Description: The DWService to remotly control your machine - abused by attackers
        // Reference: https://github.com/dwservice/agent
        $string26 = /cd12e8a285c77102487f04726b91bc649f9ad087a1e9a5546124a0cc7480c221/ nocase ascii wide
        // Description: The DWService to remotly control your machine - abused by attackers
        // Reference: https://github.com/dwservice/agent
        $string27 = /d2b2455b755476d0b35c721ccdb84432e51812ab646a9210137c1e85b90d7de4/ nocase ascii wide
        // Description: The DWService to remotly control your machine - abused by attackers
        // Reference: https://github.com/dwservice/agent
        $string28 = /dwagent_install\.log/ nocase ascii wide
        // Description: The DWService to remotly control your machine - abused by attackers
        // Reference: https://github.com/dwservice/agent
        $string29 = /dwagent_unistall\.log/ nocase ascii wide
        // Description: The DWService to remotly control your machine - abused by attackers
        // Reference: https://github.com/dwservice/agent
        $string30 = /dwaggdi_x86_32\.dll/ nocase ascii wide
        // Description: The DWService to remotly control your machine - abused by attackers
        // Reference: https://github.com/dwservice/agent
        $string31 = /dwaggdi_x86_64\.dll/ nocase ascii wide
        // Description: The DWService to remotly control your machine - abused by attackers
        // Reference: https://github.com/dwservice/agent
        $string32 = /dwagscreencapture\.dll/ nocase ascii wide
        // Description: The DWService to remotly control your machine - abused by attackers
        // Reference: https://github.com/dwservice/agent
        $string33 = /dwagscreencapturebitblt\.dll/ nocase ascii wide
        // Description: The DWService to remotly control your machine - abused by attackers
        // Reference: https://github.com/dwservice/agent
        $string34 = /dwagscreencapturedesktopduplication\.dll/ nocase ascii wide
        // Description: The DWService to remotly control your machine - abused by attackers
        // Reference: https://github.com/dwservice/agent
        $string35 = /dwservice\/agent/ nocase ascii wide
        // Description: The DWService to remotly control your machine - abused by attackers
        // Reference: https://github.com/dwservice/agent
        $string36 = /Program\sFiles\\DWAgent/ nocase ascii wide
        // Description: The DWService to remotly control your machine - abused by attackers
        // Reference: https://github.com/dwservice/agent
        $string37 = /www\.dwservice\.net/ nocase ascii wide

    condition:
        any of them
}

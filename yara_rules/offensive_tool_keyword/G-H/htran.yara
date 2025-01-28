rule htran
{
    meta:
        description = "Detection patterns for the tool 'htran' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "htran"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: proxies connections through intermediate hops and aids users in disguising their true geographical location. It can be used by adversaries to hide their location when interacting with the victim networks
        // Reference: https://github.com/HiwinCN/Htran
        $string1 = /\sCode\sby\slion\s\&\sbkbll\,\sWelcome\sto\shttp\:\/\/www\.cnhonker\.com\s/ nocase ascii wide
        // Description: proxies connections through intermediate hops and aids users in disguising their true geographical location. It can be used by adversaries to hide their location when interacting with the victim networks
        // Reference: https://github.com/HiwinCN/Htran
        $string2 = " -tran <ConnectPort> <TransmitHost> <TransmitPort>" nocase ascii wide
        // Description: proxies connections through intermediate hops and aids users in disguising their true geographical location. It can be used by adversaries to hide their location when interacting with the victim networks
        // Reference: https://github.com/HiwinCN/Htran
        $string3 = "/bin/htran"
        // Description: proxies connections through intermediate hops and aids users in disguising their true geographical location. It can be used by adversaries to hide their location when interacting with the victim networks
        // Reference: https://github.com/HiwinCN/Htran
        $string4 = /\/htran\.exe/ nocase ascii wide
        // Description: proxies connections through intermediate hops and aids users in disguising their true geographical location. It can be used by adversaries to hide their location when interacting with the victim networks
        // Reference: https://github.com/HiwinCN/Htran
        $string5 = /\/HTran\.git/ nocase ascii wide
        // Description: proxies connections through intermediate hops and aids users in disguising their true geographical location. It can be used by adversaries to hide their location when interacting with the victim networks
        // Reference: https://github.com/HiwinCN/Htran
        $string6 = /\/Htran\-master\.zip/ nocase ascii wide
        // Description: proxies connections through intermediate hops and aids users in disguising their true geographical location. It can be used by adversaries to hide their location when interacting with the victim networks
        // Reference: https://github.com/HiwinCN/Htran
        $string7 = /\[\+\]\sOK\!\sI\sClosed\sThe\sTwo\sSocket\./ nocase ascii wide
        // Description: proxies connections through intermediate hops and aids users in disguising their true geographical location. It can be used by adversaries to hide their location when interacting with the victim networks
        // Reference: https://github.com/HiwinCN/Htran
        $string8 = /\\htran\.exe/ nocase ascii wide
        // Description: proxies connections through intermediate hops and aids users in disguising their true geographical location. It can be used by adversaries to hide their location when interacting with the victim networks
        // Reference: https://github.com/HiwinCN/Htran
        $string9 = /\\Htran\-master\.zip/ nocase ascii wide
        // Description: proxies connections through intermediate hops and aids users in disguising their true geographical location. It can be used by adversaries to hide their location when interacting with the victim networks
        // Reference: https://github.com/HiwinCN/Htran
        $string10 = "= HUC Packet Transmit Tool V" nocase ascii wide
        // Description: proxies connections through intermediate hops and aids users in disguising their true geographical location. It can be used by adversaries to hide their location when interacting with the victim networks
        // Reference: https://github.com/HiwinCN/Htran
        $string11 = "======================== htran V%s =======================" nocase ascii wide
        // Description: proxies connections through intermediate hops and aids users in disguising their true geographical location. It can be used by adversaries to hide their location when interacting with the victim networks
        // Reference: https://github.com/HiwinCN/Htran
        $string12 = "23092e288c27221ba793178e177a04309cf5c6073e2a022f5c4035252d69086d" nocase ascii wide
        // Description: proxies connections through intermediate hops and aids users in disguising their true geographical location. It can be used by adversaries to hide their location when interacting with the victim networks
        // Reference: https://github.com/HiwinCN/Htran
        $string13 = "b54ab14a7ad0460c7ac6416a9ad01e7015d32573571114b569f4769a2eb12e70" nocase ascii wide
        // Description: proxies connections through intermediate hops and aids users in disguising their true geographical location. It can be used by adversaries to hide their location when interacting with the victim networks
        // Reference: https://github.com/HiwinCN/Htran
        $string14 = "e5aef5ed2d977915b2288135ea8689b1fb15f619021a8a5b788a475a068cde8b" nocase ascii wide
        // Description: proxies connections through intermediate hops and aids users in disguising their true geographical location. It can be used by adversaries to hide their location when interacting with the victim networks
        // Reference: https://github.com/HiwinCN/Htran
        $string15 = "HiwinCN/Htran" nocase ascii wide
        // Description: proxies connections through intermediate hops and aids users in disguising their true geographical location. It can be used by adversaries to hide their location when interacting with the victim networks
        // Reference: https://github.com/HiwinCN/Htran
        $string16 = /HTran\.cpp\s\-\sHUC\sPacket\sTransmit\sTool\./ nocase ascii wide
        // Description: proxies connections through intermediate hops and aids users in disguising their true geographical location. It can be used by adversaries to hide their location when interacting with the victim networks
        // Reference: https://github.com/HiwinCN/Htran
        $string17 = "-slave  <ConnectHost> <ConnectPort> <TransmitHost> <TransmitPort>" nocase ascii wide

    condition:
        any of them
}

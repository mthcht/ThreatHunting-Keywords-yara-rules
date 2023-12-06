rule KeePwn
{
    meta:
        description = "Detection patterns for the tool 'KeePwn' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KeePwn"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string1 = /\s\-\-bruteforce\s.{0,1000}\.kdbx/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string2 = /\s\-\-dump_file\sKeepass\.exe\.dmp/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string3 = /\sKeePwn\.py/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string4 = /\s\-\-plugin\sKeeFarceRebornPlugin\.dll/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string5 = /\/keepwn\.core/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string6 = /\/KeePwn\.git/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string7 = /\/KeePwn\.py/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string8 = /\/keepwn\.utils/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string9 = /\/KeePwn\/keepwn\// nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string10 = /\/KeePwn\-0\.3\// nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string11 = /\\KeePwn\.py/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string12 = /\\KeePwn\\keepwn\\/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string13 = /\\KeePwn\-0\.3\\/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string14 = /\\KeePwn\-main\\/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string15 = /keepass\-password\-dumper/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string16 = /KeePwn\s\-\-/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string17 = /KeePwn\sparse_dump\s/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string18 = /KeePwn\splugin\s/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string19 = /KeePwn\strigger\s/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string20 = /KeePwn\sv.{0,1000}\s\-\sby\sJulien\sBEDEL/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string21 = /keepwn\.__main__:main/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string22 = /keepwn\.core\.parse_dump/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string23 = /keepwn\.core\.plugin/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string24 = /keepwn\.core\.search/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string25 = /keepwn\.core\.trigger/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string26 = /KeePwn\.py\s/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string27 = /KeePwn\-main\.zip/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string28 = /Orange\-Cyberdefense\/KeePwn/ nocase ascii wide

    condition:
        any of them
}

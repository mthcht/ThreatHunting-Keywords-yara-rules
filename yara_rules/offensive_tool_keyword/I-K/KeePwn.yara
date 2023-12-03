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
        $string1 = /.{0,1000}\s\-\-bruteforce\s.{0,1000}\.kdbx.{0,1000}/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string2 = /.{0,1000}\s\-\-dump_file\sKeepass\.exe\.dmp.{0,1000}/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string3 = /.{0,1000}\sKeePwn\.py.{0,1000}/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string4 = /.{0,1000}\s\-\-plugin\sKeeFarceRebornPlugin\.dll.{0,1000}/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string5 = /.{0,1000}\/keepwn\.core.{0,1000}/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string6 = /.{0,1000}\/KeePwn\.git.{0,1000}/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string7 = /.{0,1000}\/KeePwn\.py.{0,1000}/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string8 = /.{0,1000}\/keepwn\.utils.{0,1000}/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string9 = /.{0,1000}\/KeePwn\/keepwn\/.{0,1000}/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string10 = /.{0,1000}\/KeePwn\-0\.3\/.{0,1000}/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string11 = /.{0,1000}\\KeePwn\.py.{0,1000}/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string12 = /.{0,1000}\\KeePwn\\keepwn\\.{0,1000}/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string13 = /.{0,1000}\\KeePwn\-0\.3\\.{0,1000}/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string14 = /.{0,1000}\\KeePwn\-main\\.{0,1000}/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string15 = /.{0,1000}keepass\-password\-dumper.{0,1000}/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string16 = /.{0,1000}KeePwn\s\-\-.{0,1000}/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string17 = /.{0,1000}KeePwn\sparse_dump\s.{0,1000}/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string18 = /.{0,1000}KeePwn\splugin\s.{0,1000}/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string19 = /.{0,1000}KeePwn\strigger\s.{0,1000}/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string20 = /.{0,1000}KeePwn\sv.{0,1000}\s\-\sby\sJulien\sBEDEL.{0,1000}/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string21 = /.{0,1000}keepwn\.__main__:main.{0,1000}/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string22 = /.{0,1000}keepwn\.core\.parse_dump.{0,1000}/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string23 = /.{0,1000}keepwn\.core\.plugin.{0,1000}/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string24 = /.{0,1000}keepwn\.core\.search.{0,1000}/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string25 = /.{0,1000}keepwn\.core\.trigger.{0,1000}/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string26 = /.{0,1000}KeePwn\.py\s.{0,1000}/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string27 = /.{0,1000}KeePwn\-main\.zip.{0,1000}/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string28 = /.{0,1000}Orange\-Cyberdefense\/KeePwn.{0,1000}/ nocase ascii wide

    condition:
        any of them
}

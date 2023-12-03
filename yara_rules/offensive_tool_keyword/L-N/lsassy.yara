rule lsassy
{
    meta:
        description = "Detection patterns for the tool 'lsassy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "lsassy"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string1 = /.{0,1000}\s\-\-dump\-name\s.{0,1000}lsass.{0,1000}/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string2 = /.{0,1000}\slsassy.{0,1000}/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string3 = /.{0,1000}\/dumpmethod\/.{0,1000}\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string4 = /.{0,1000}\/lsassy.{0,1000}/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string5 = /.{0,1000}\/rawrpc\.py.{0,1000}/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string6 = /.{0,1000}\/silentprocessexit\.py.{0,1000}/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string7 = /.{0,1000}dllinject\.py.{0,1000}/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string8 = /.{0,1000}dumpert\.py.{0,1000}/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string9 = /.{0,1000}dumpert_path\=.{0,1000}/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string10 = /.{0,1000}dumpertdll.{0,1000}/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string11 = /.{0,1000}edrsandblast\.py.{0,1000}/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string12 = /.{0,1000}hackndo\@gmail\.com.{0,1000}/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string13 = /.{0,1000}impacketfile\.py.{0,1000}/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string14 = /.{0,1000}lsassy\s.{0,1000}/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string15 = /.{0,1000}lsassy\..{0,1000}/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string16 = /.{0,1000}lsassy\/dumpmethod.{0,1000}/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string17 = /.{0,1000}lsassy\-linux\-x64\-.{0,1000}/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string18 = /.{0,1000}lsassy\-MacOS\-x64\-.{0,1000}/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string19 = /.{0,1000}lsassy\-windows\-x64\-.{0,1000}\.exe/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string20 = /.{0,1000}\-m\sdumpert\s.{0,1000}/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string21 = /.{0,1000}nanodump\..{0,1000}/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string22 = /.{0,1000}nanodump_ssp.{0,1000}/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string23 = /.{0,1000}nanodump_ssp_embedded\..{0,1000}/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string24 = /.{0,1000}ppldump\.py.{0,1000}/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string25 = /.{0,1000}ppldump_embedded.{0,1000}/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string26 = /.{0,1000}procdump_embedded.{0,1000}/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string27 = /.{0,1000}procdump_path\=.{0,1000}/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string28 = /.{0,1000}rdrleakdiag\.py.{0,1000}/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string29 = /.{0,1000}smb_stealth\.py.{0,1000}/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string30 = /.{0,1000}sqldumper\.py.{0,1000}/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string31 = /.{0,1000}test_lsassy\..{0,1000}/ nocase ascii wide

    condition:
        any of them
}

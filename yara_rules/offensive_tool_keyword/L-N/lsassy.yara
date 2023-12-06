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
        $string1 = /\s\-\-dump\-name\s.{0,1000}lsass/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string2 = /\slsassy/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string3 = /\/dumpmethod\/.{0,1000}\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string4 = /\/lsassy/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string5 = /\/rawrpc\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string6 = /\/silentprocessexit\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string7 = /dllinject\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string8 = /dumpert\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string9 = /dumpert_path\=/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string10 = /dumpertdll/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string11 = /edrsandblast\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string12 = /hackndo\@gmail\.com/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string13 = /impacketfile\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string14 = /lsassy\s/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string15 = /lsassy\./ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string16 = /lsassy\/dumpmethod/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string17 = /lsassy\-linux\-x64\-/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string18 = /lsassy\-MacOS\-x64\-/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string19 = /lsassy\-windows\-x64\-.{0,1000}\.exe/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string20 = /\-m\sdumpert\s/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string21 = /nanodump\./ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string22 = /nanodump_ssp/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string23 = /nanodump_ssp_embedded\./ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string24 = /ppldump\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string25 = /ppldump_embedded/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string26 = /procdump_embedded/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string27 = /procdump_path\=/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string28 = /rdrleakdiag\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string29 = /smb_stealth\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string30 = /sqldumper\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/Hackndo/lsassy
        $string31 = /test_lsassy\./ nocase ascii wide

    condition:
        any of them
}

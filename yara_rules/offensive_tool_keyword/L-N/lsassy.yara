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
        // Reference: https://github.com/login-securite/lsassy
        $string1 = /\s\-\-dump\-name\s.{0,1000}lsass/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string2 = /\slsassy/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string3 = /\/dumpmethod\/.{0,1000}\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string4 = /\/lsassy/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string5 = /\/rawrpc\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string6 = /\/silentprocessexit\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string7 = /dllinject\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string8 = /dumpert\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string9 = /dumpert_path\=/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string10 = /dumpertdll/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string11 = /edrsandblast\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string12 = /hackndo\@gmail\.com/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string13 = /impacketfile\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string14 = /login\-securite\/lsassy/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string15 = /lsassy\s/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string16 = /lsassy\./ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string17 = /lsassy\/dumpmethod/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string18 = /lsassy\-linux\-x64\-/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string19 = /lsassy\-MacOS\-x64\-/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string20 = /lsassy\-windows\-x64\-.{0,1000}\.exe/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string21 = /\-m\sdumpert\s/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string22 = /nanodump\./ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string23 = /nanodump_ssp/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string24 = /nanodump_ssp_embedded\./ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string25 = /ppldump\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string26 = /ppldump_embedded/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string27 = /procdump_embedded/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string28 = /procdump_path\=/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string29 = /rdrleakdiag\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string30 = /smb_stealth\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string31 = /sqldumper\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string32 = /test_lsassy\./ nocase ascii wide

    condition:
        any of them
}

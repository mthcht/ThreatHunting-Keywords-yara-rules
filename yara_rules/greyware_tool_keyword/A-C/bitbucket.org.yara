rule bitbucket_org
{
    meta:
        description = "Detection patterns for the tool 'bitbucket.org' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bitbucket.org"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: legitimate hosting platform abused by malwares like lummastealer
        // Reference: N/A
        $string1 = /https\:\/\/bitbucket\.org\/.{0,1000}\/downloads\/.{0,1000}\.bat/ nocase ascii wide
        // Description: legitimate hosting platform abused by malwares like lummastealer
        // Reference: N/A
        $string2 = /https\:\/\/bitbucket\.org\/.{0,1000}\/downloads\/.{0,1000}\.dll/ nocase ascii wide
        // Description: legitimate hosting platform abused by malwares like lummastealer
        // Reference: N/A
        $string3 = /https\:\/\/bitbucket\.org\/.{0,1000}\/downloads\/.{0,1000}\.dll/ nocase ascii wide
        // Description: legitimate hosting platform abused by malwares like lummastealer
        // Reference: N/A
        $string4 = /https\:\/\/bitbucket\.org\/.{0,1000}\/downloads\/.{0,1000}\.exe/ nocase ascii wide
        // Description: legitimate hosting platform abused by malwares like lummastealer
        // Reference: N/A
        $string5 = /https\:\/\/bitbucket\.org\/.{0,1000}\/downloads\/.{0,1000}\.ps1/ nocase ascii wide
        // Description: legitimate hosting platform abused by malwares like lummastealer
        // Reference: N/A
        $string6 = /https\:\/\/bitbucket\.org\/.{0,1000}\/downloads\/.{0,1000}\.rar/ nocase ascii wide
        // Description: legitimate hosting platform abused by malwares like lummastealer
        // Reference: N/A
        $string7 = /https\:\/\/bitbucket\.org\/.{0,1000}\/downloads\/.{0,1000}\.zip/ nocase ascii wide

    condition:
        any of them
}

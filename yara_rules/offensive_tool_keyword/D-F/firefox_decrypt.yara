rule firefox_decrypt
{
    meta:
        description = "Detection patterns for the tool 'firefox_decrypt' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "firefox_decrypt"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Firefox Decrypt is a tool to extract passwords from Mozilla
        // Reference: https://github.com/unode/firefox_decrypt
        $string1 = /.{0,1000}\/firefox_decrypt\.git.{0,1000}/ nocase ascii wide
        // Description: Firefox Decrypt is a tool to extract passwords from Mozilla
        // Reference: https://github.com/unode/firefox_decrypt
        $string2 = /.{0,1000}firefox_decrypt\.py.{0,1000}/ nocase ascii wide
        // Description: Firefox Decrypt is a tool to extract passwords from Mozilla
        // Reference: https://github.com/unode/firefox_decrypt
        $string3 = /.{0,1000}firefox_decrypt\-main.{0,1000}/ nocase ascii wide
        // Description: Firefox Decrypt is a tool to extract passwords from Mozilla
        // Reference: https://github.com/unode/firefox_decrypt
        $string4 = /.{0,1000}unode\/firefox_decrypt.{0,1000}/ nocase ascii wide

    condition:
        any of them
}

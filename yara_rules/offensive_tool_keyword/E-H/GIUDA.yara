rule GIUDA
{
    meta:
        description = "Detection patterns for the tool 'GIUDA' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GIUDA"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Ask a TGS on behalf of another user without password
        // Reference: https://github.com/foxlox/GIUDA
        $string1 = /.{0,1000}\s\-runaslsass.{0,1000}/ nocase ascii wide
        // Description: Ask a TGS on behalf of another user without password
        // Reference: https://github.com/foxlox/GIUDA
        $string2 = /.{0,1000}\.exe\s\-gettgs\s\-luid:.{0,1000}/ nocase ascii wide
        // Description: Ask a TGS on behalf of another user without password
        // Reference: https://github.com/foxlox/GIUDA
        $string3 = /.{0,1000}\.exe\s\-ptt\sticket:.{0,1000}\.kirbi.{0,1000}/ nocase ascii wide
        // Description: Ask a TGS on behalf of another user without password
        // Reference: https://github.com/foxlox/GIUDA
        $string4 = /.{0,1000}GIUDA.{0,1000}\s\-askluids.{0,1000}/ nocase ascii wide
        // Description: Ask a TGS on behalf of another user without password
        // Reference: https://github.com/foxlox/GIUDA
        $string5 = /.{0,1000}GIUDA\-main\.zip.{0,1000}/ nocase ascii wide
        // Description: Ask a TGS on behalf of another user without password
        // Reference: https://github.com/foxlox/GIUDA
        $string6 = /.{0,1000}guida\.exe\s\-.{0,1000}/ nocase ascii wide

    condition:
        any of them
}

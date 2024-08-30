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
        $string1 = /\s\-runaslsass/ nocase ascii wide
        // Description: Ask a TGS on behalf of another user without password
        // Reference: https://github.com/foxlox/GIUDA
        $string2 = /\.exe\s\-gettgs\s\-luid\:/ nocase ascii wide
        // Description: Ask a TGS on behalf of another user without password
        // Reference: https://github.com/foxlox/GIUDA
        $string3 = /\.exe\s\-ptt\sticket\:.{0,1000}\.kirbi/ nocase ascii wide
        // Description: Ask a TGS on behalf of another user without password
        // Reference: https://github.com/foxlox/GIUDA
        $string4 = /GIUDA.{0,1000}\s\-askluids/ nocase ascii wide
        // Description: Ask a TGS on behalf of another user without password
        // Reference: https://github.com/foxlox/GIUDA
        $string5 = /GIUDA\-main\.zip/ nocase ascii wide
        // Description: Ask a TGS on behalf of another user without password
        // Reference: https://github.com/foxlox/GIUDA
        $string6 = /guida\.exe\s\-/ nocase ascii wide

    condition:
        any of them
}

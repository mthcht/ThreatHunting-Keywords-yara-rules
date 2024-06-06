rule SharpAppLocker
{
    meta:
        description = "Detection patterns for the tool 'SharpAppLocker' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpAppLocker"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Useful when you already bypassed AppLocker initially and you don't want to leave PS logs
        // Reference: https://github.com/Flangvik/SharpAppLocker
        $string1 = /\sby\sFlangvik\s\&\sJean_Maes_1994/ nocase ascii wide
        // Description: Useful when you already bypassed AppLocker initially and you don't want to leave PS logs
        // Reference: https://github.com/Flangvik/SharpAppLocker
        $string2 = /\.exe\s\-\-effective\s\-\-allow\s\-\-outfile\s\"C\:\\Windows\\Tasks\\Rules\.json\"/ nocase ascii wide
        // Description: Useful when you already bypassed AppLocker initially and you don't want to leave PS logs
        // Reference: https://github.com/Flangvik/SharpAppLocker
        $string3 = /\.exe\s\-\-effective\s\-\-allow\s\-\-rules\=\"FileHashRule\,FilePathRule\"\s\-\-outfile\=/ nocase ascii wide
        // Description: Useful when you already bypassed AppLocker initially and you don't want to leave PS logs
        // Reference: https://github.com/Flangvik/SharpAppLocker
        $string4 = /\/SharpAppLocker\.git/ nocase ascii wide
        // Description: Useful when you already bypassed AppLocker initially and you don't want to leave PS logs
        // Reference: https://github.com/Flangvik/SharpAppLocker
        $string5 = /\\SharpAppLocker\./ nocase ascii wide
        // Description: Useful when you already bypassed AppLocker initially and you don't want to leave PS logs
        // Reference: https://github.com/Flangvik/SharpAppLocker
        $string6 = /d43fc4c6e67a332b6abbb4b35186e9a20fa962c6aa4521f49b19f5bf372262d2/ nocase ascii wide
        // Description: Useful when you already bypassed AppLocker initially and you don't want to leave PS logs
        // Reference: https://github.com/Flangvik/SharpAppLocker
        $string7 = /f8e1e243c0648d5bfcd2bb529571b4506f26897574537cffbf1399a171746713/ nocase ascii wide
        // Description: Useful when you already bypassed AppLocker initially and you don't want to leave PS logs
        // Reference: https://github.com/Flangvik/SharpAppLocker
        $string8 = /FE102D27\-DEC4\-42E2\-BF69\-86C79E08B67D/ nocase ascii wide
        // Description: Useful when you already bypassed AppLocker initially and you don't want to leave PS logs
        // Reference: https://github.com/Flangvik/SharpAppLocker
        $string9 = /Flangvik\/SharpAppLocker/ nocase ascii wide
        // Description: Useful when you already bypassed AppLocker initially and you don't want to leave PS logs
        // Reference: https://github.com/Flangvik/SharpAppLocker
        $string10 = /SharpAppLocker\.exe/ nocase ascii wide

    condition:
        any of them
}

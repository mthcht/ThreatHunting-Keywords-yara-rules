rule padre
{
    meta:
        description = "Detection patterns for the tool 'padre' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "padre"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: padre?is an advanced exploiter for Padding Oracle attacks against CBC mode encryption
        // Reference: https://github.com/glebarez/padre
        $string1 = /.{0,1000}\sgo\sbuild\s\-o\spadre\s\..{0,1000}/ nocase ascii wide
        // Description: padre?is an advanced exploiter for Padding Oracle attacks against CBC mode encryption
        // Reference: https://github.com/glebarez/padre
        $string2 = /.{0,1000}\/padre\/pkg\/exploit.{0,1000}/ nocase ascii wide
        // Description: padre?is an advanced exploiter for Padding Oracle attacks against CBC mode encryption
        // Reference: https://github.com/glebarez/padre
        $string3 = /.{0,1000}\\padre\\pkg\\exploit.{0,1000}/ nocase ascii wide
        // Description: padre?is an advanced exploiter for Padding Oracle attacks against CBC mode encryption
        // Reference: https://github.com/glebarez/padre
        $string4 = /.{0,1000}github.{0,1000}\/padre\.git.{0,1000}/ nocase ascii wide
        // Description: padre?is an advanced exploiter for Padding Oracle attacks against CBC mode encryption
        // Reference: https://github.com/glebarez/padre
        $string5 = /.{0,1000}glebarez\/padre.{0,1000}/ nocase ascii wide
        // Description: padre?is an advanced exploiter for Padding Oracle attacks against CBC mode encryption
        // Reference: https://github.com/glebarez/padre
        $string6 = /.{0,1000}Gw3kg8e3ej4ai9wffn\%2Fd0uRqKzyaPfM2UFq\%2F8dWmoW4wnyKZhx07Bg\=\=.{0,1000}/ nocase ascii wide
        // Description: padre?is an advanced exploiter for Padding Oracle attacks against CBC mode encryption
        // Reference: https://github.com/glebarez/padre
        $string7 = /.{0,1000}\-p\s5000:5000\spador_vuln_server.{0,1000}/ nocase ascii wide
        // Description: padre?is an advanced exploiter for Padding Oracle attacks against CBC mode encryption
        // Reference: https://github.com/glebarez/padre
        $string8 = /.{0,1000}padre\s\-u\s.{0,1000}http.{0,1000}:\/\/.{0,1000}/ nocase ascii wide
        // Description: padre?is an advanced exploiter for Padding Oracle attacks against CBC mode encryption
        // Reference: https://github.com/glebarez/padre
        $string9 = /.{0,1000}padre\-master\.zip.{0,1000}/ nocase ascii wide

    condition:
        any of them
}

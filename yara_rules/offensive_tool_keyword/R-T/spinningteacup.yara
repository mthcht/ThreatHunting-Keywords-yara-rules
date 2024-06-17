rule spinningteacup
{
    meta:
        description = "Detection patterns for the tool 'spinningteacup' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "spinningteacup"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: identify different parts of a vba script and perform substitutions
        // Reference: https://github.com/trustedsec/The_Shelf
        $string1 = /\sspinningteacup\.py/ nocase ascii wide
        // Description: identify different parts of a vba script and perform substitutions
        // Reference: https://github.com/trustedsec/The_Shelf
        $string2 = /\svbarandomizer\.py/ nocase ascii wide
        // Description: identify different parts of a vba script and perform substitutions
        // Reference: https://github.com/trustedsec/The_Shelf
        $string3 = /\"This\sis\sa\smacro\sobfuscating\sframework\"/ nocase ascii wide
        // Description: identify different parts of a vba script and perform substitutions
        // Reference: https://github.com/trustedsec/The_Shelf
        $string4 = /\.py\s.{0,1000}\.vba\s.{0,1000}\.vba\s\s\-\-norandomvariables\s\-\-math/ nocase ascii wide
        // Description: identify different parts of a vba script and perform substitutions
        // Reference: https://github.com/trustedsec/The_Shelf
        $string5 = /\.py\s.{0,1000}\.vba\s.{0,1000}\.vba\s\s\-\-wordlistpath\s.{0,1000}\s\-\-encodestring/ nocase ascii wide
        // Description: identify different parts of a vba script and perform substitutions
        // Reference: https://github.com/trustedsec/The_Shelf
        $string6 = /\.py\s.{0,1000}\.vba\s.{0,1000}\.vba\s\-\-randomcuts\s5\s10\s\-\-norandomint/ nocase ascii wide
        // Description: identify different parts of a vba script and perform substitutions
        // Reference: https://github.com/trustedsec/The_Shelf
        $string7 = /\.py\s.{0,1000}\.vba\s.{0,1000}\.vba\s\-\-usebusinesswords\s\-\-encodestring_calls/ nocase ascii wide
        // Description: identify different parts of a vba script and perform substitutions
        // Reference: https://github.com/trustedsec/The_Shelf
        $string8 = /\.py\s.{0,1000}\.vba\s.{0,1000}\.vba\s\-\-usebusinesswords\s\-\-math/ nocase ascii wide
        // Description: identify different parts of a vba script and perform substitutions
        // Reference: https://github.com/trustedsec/The_Shelf
        $string9 = /\/spinningteacup\.py/ nocase ascii wide
        // Description: identify different parts of a vba script and perform substitutions
        // Reference: https://github.com/trustedsec/The_Shelf
        $string10 = /\/vbarandomizer\.py/ nocase ascii wide
        // Description: identify different parts of a vba script and perform substitutions
        // Reference: https://github.com/trustedsec/The_Shelf
        $string11 = /\\spinningteacup\.py/ nocase ascii wide
        // Description: identify different parts of a vba script and perform substitutions
        // Reference: https://github.com/trustedsec/The_Shelf
        $string12 = /\\vbarandomizer\.py/ nocase ascii wide
        // Description: identify different parts of a vba script and perform substitutions
        // Reference: https://github.com/trustedsec/The_Shelf
        $string13 = /577b85630ecfd64d6817de11c4abf256512d299f70998c8c531202272123b202/ nocase ascii wide
        // Description: identify different parts of a vba script and perform substitutions
        // Reference: https://github.com/trustedsec/The_Shelf
        $string14 = /attempt\sto\srandomize\sscript\swithout\ssetting\sall\srandomizations\smethods/ nocase ascii wide
        // Description: identify different parts of a vba script and perform substitutions
        // Reference: https://github.com/trustedsec/The_Shelf
        $string15 = /from\srandomizers\.vbarandomizer\simport\svbaRandomizer/ nocase ascii wide
        // Description: identify different parts of a vba script and perform substitutions
        // Reference: https://github.com/trustedsec/The_Shelf
        $string16 = /your\sscript\shas\sbeen\sobfuscated\sand\soutput\sto\s/ nocase ascii wide

    condition:
        any of them
}

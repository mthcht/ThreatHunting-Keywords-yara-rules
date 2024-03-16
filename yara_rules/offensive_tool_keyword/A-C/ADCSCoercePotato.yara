rule ADCSCoercePotato
{
    meta:
        description = "Detection patterns for the tool 'ADCSCoercePotato' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ADCSCoercePotato"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: coercing machine authentication but specific for ADCS server
        // Reference: https://github.com/decoder-it/ADCSCoercePotato
        $string1 = /\.asp\s\-\-adcs\s\-\-template\sMachine\s\-smb2support/ nocase ascii wide
        // Description: coercing machine authentication but specific for ADCS server
        // Reference: https://github.com/decoder-it/ADCSCoercePotato
        $string2 = /\/ADCSCoercePotato\.git/ nocase ascii wide
        // Description: coercing machine authentication but specific for ADCS server
        // Reference: https://github.com/decoder-it/ADCSCoercePotato
        $string3 = /\/ADCSCoercePotato\// nocase ascii wide
        // Description: coercing machine authentication but specific for ADCS server
        // Reference: https://github.com/decoder-it/ADCSCoercePotato
        $string4 = /\[\!\]\sCouldn\'t\scommunicate\swith\sthe\sfake\sRPC\sServer/ nocase ascii wide
        // Description: coercing machine authentication but specific for ADCS server
        // Reference: https://github.com/decoder-it/ADCSCoercePotato
        $string5 = /\[\+\]\sGot\sNTLM\stype\s3\sAUTH\smessage\sfrom\s.{0,1000}\s\swith\shostname\s/ nocase ascii wide
        // Description: coercing machine authentication but specific for ADCS server
        // Reference: https://github.com/decoder-it/ADCSCoercePotato
        $string6 = /\\ADCSCoercePotato\\/ nocase ascii wide
        // Description: coercing machine authentication but specific for ADCS server
        // Reference: https://github.com/decoder-it/ADCSCoercePotato
        $string7 = /\\MSFRottenPotato\.h/ nocase ascii wide
        // Description: coercing machine authentication but specific for ADCS server
        // Reference: https://github.com/decoder-it/ADCSCoercePotato
        $string8 = /4164003E\-BA47\-4A95\-8586\-D5AAC399C050/ nocase ascii wide
        // Description: coercing machine authentication but specific for ADCS server
        // Reference: https://github.com/decoder-it/ADCSCoercePotato
        $string9 = /ADCSCoercePotato\.cpp/ nocase ascii wide
        // Description: coercing machine authentication but specific for ADCS server
        // Reference: https://github.com/decoder-it/ADCSCoercePotato
        $string10 = /ADCSCoercePotato\.exe/ nocase ascii wide
        // Description: coercing machine authentication but specific for ADCS server
        // Reference: https://github.com/decoder-it/ADCSCoercePotato
        $string11 = /ADCSCoercePotato\.sln/ nocase ascii wide
        // Description: coercing machine authentication but specific for ADCS server
        // Reference: https://github.com/decoder-it/ADCSCoercePotato
        $string12 = /ADCSCoercePotato\.vcxproj/ nocase ascii wide
        // Description: coercing machine authentication but specific for ADCS server
        // Reference: https://github.com/decoder-it/ADCSCoercePotato
        $string13 = /ADCSCoercePotato\\n\-\s\@decoder_it\s2024\\/ nocase ascii wide
        // Description: coercing machine authentication but specific for ADCS server
        // Reference: https://github.com/decoder-it/ADCSCoercePotato
        $string14 = /decoder\-it\/ADCSCoercePotato/ nocase ascii wide
        // Description: coercing machine authentication but specific for ADCS server
        // Reference: https://github.com/decoder-it/ADCSCoercePotato
        $string15 = /include\s\"MSFRottenPotato\.h\"/ nocase ascii wide
        // Description: coercing machine authentication but specific for ADCS server
        // Reference: https://github.com/decoder-it/ADCSCoercePotato
        $string16 = /int\sPotatoAPI\:\:findNTLMBytes/ nocase ascii wide

    condition:
        any of them
}

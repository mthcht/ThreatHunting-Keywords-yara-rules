rule ShuckNT
{
    meta:
        description = "Detection patterns for the tool 'ShuckNT' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ShuckNT"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: ShuckNT is the script of Shuck.sh online service for on-premise use. It is design to dowgrade - convert - dissect and shuck authentication token based on Data Encryption Standard (DES)
        // Reference: https://github.com/yanncam/ShuckNT
        $string1 = /.{0,1000}\/\/shuck\.sh.{0,1000}/ nocase ascii wide
        // Description: ShuckNT is the script of Shuck.sh online service for on-premise use. It is design to dowgrade - convert - dissect and shuck authentication token based on Data Encryption Standard (DES)
        // Reference: https://github.com/yanncam/ShuckNT
        $string2 = /.{0,1000}\/get\-shucking\.php.{0,1000}/ nocase ascii wide
        // Description: ShuckNT is the script of Shuck.sh online service for on-premise use. It is design to dowgrade - convert - dissect and shuck authentication token based on Data Encryption Standard (DES)
        // Reference: https://github.com/yanncam/ShuckNT
        $string3 = /.{0,1000}\/ShuckNT\.git.{0,1000}/ nocase ascii wide
        // Description: ShuckNT is the script of Shuck.sh online service for on-premise use. It is design to dowgrade - convert - dissect and shuck authentication token based on Data Encryption Standard (DES)
        // Reference: https://github.com/yanncam/ShuckNT
        $string4 = /.{0,1000}99\$1a7F1qr2HihoXfs\/56u5XMdpDZ83N6hW\/HI\=.{0,1000}/ nocase ascii wide
        // Description: ShuckNT is the script of Shuck.sh online service for on-premise use. It is design to dowgrade - convert - dissect and shuck authentication token based on Data Encryption Standard (DES)
        // Reference: https://github.com/yanncam/ShuckNT
        $string5 = /.{0,1000}pwned\-passwords\-ntlm.{0,1000}/ nocase ascii wide
        // Description: ShuckNT is the script of Shuck.sh online service for on-premise use. It is design to dowgrade - convert - dissect and shuck authentication token based on Data Encryption Standard (DES)
        // Reference: https://github.com/yanncam/ShuckNT
        $string6 = /.{0,1000}shucknt\.php.{0,1000}/ nocase ascii wide
        // Description: ShuckNT is the script of Shuck.sh online service for on-premise use. It is design to dowgrade - convert - dissect and shuck authentication token based on Data Encryption Standard (DES)
        // Reference: https://github.com/yanncam/ShuckNT
        $string7 = /.{0,1000}ShuckNT\-main.{0,1000}/ nocase ascii wide
        // Description: ShuckNT is the script of Shuck.sh online service for on-premise use. It is design to dowgrade - convert - dissect and shuck authentication token based on Data Encryption Standard (DES)
        // Reference: https://github.com/yanncam/ShuckNT
        $string8 = /.{0,1000}wordlist\-nthash\-reversed.{0,1000}/ nocase ascii wide
        // Description: ShuckNT is the script of Shuck.sh online service for on-premise use. It is design to dowgrade - convert - dissect and shuck authentication token based on Data Encryption Standard (DES)
        // Reference: https://github.com/yanncam/ShuckNT
        $string9 = /.{0,1000}yanncam\/ShuckNT.{0,1000}/ nocase ascii wide

    condition:
        any of them
}

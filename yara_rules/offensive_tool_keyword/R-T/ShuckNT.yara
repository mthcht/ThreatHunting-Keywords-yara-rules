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
        $string1 = /\/\/shuck\.sh/ nocase ascii wide
        // Description: ShuckNT is the script of Shuck.sh online service for on-premise use. It is design to dowgrade - convert - dissect and shuck authentication token based on Data Encryption Standard (DES)
        // Reference: https://github.com/yanncam/ShuckNT
        $string2 = /\/get\-shucking\.php/ nocase ascii wide
        // Description: ShuckNT is the script of Shuck.sh online service for on-premise use. It is design to dowgrade - convert - dissect and shuck authentication token based on Data Encryption Standard (DES)
        // Reference: https://github.com/yanncam/ShuckNT
        $string3 = /\/ShuckNT\.git/ nocase ascii wide
        // Description: ShuckNT is the script of Shuck.sh online service for on-premise use. It is design to dowgrade - convert - dissect and shuck authentication token based on Data Encryption Standard (DES)
        // Reference: https://github.com/yanncam/ShuckNT
        $string4 = /99\$1a7F1qr2HihoXfs\/56u5XMdpDZ83N6hW\/HI\=/ nocase ascii wide
        // Description: ShuckNT is the script of Shuck.sh online service for on-premise use. It is design to dowgrade - convert - dissect and shuck authentication token based on Data Encryption Standard (DES)
        // Reference: https://github.com/yanncam/ShuckNT
        $string5 = /pwned\-passwords\-ntlm/ nocase ascii wide
        // Description: ShuckNT is the script of Shuck.sh online service for on-premise use. It is design to dowgrade - convert - dissect and shuck authentication token based on Data Encryption Standard (DES)
        // Reference: https://github.com/yanncam/ShuckNT
        $string6 = /shucknt\.php/ nocase ascii wide
        // Description: ShuckNT is the script of Shuck.sh online service for on-premise use. It is design to dowgrade - convert - dissect and shuck authentication token based on Data Encryption Standard (DES)
        // Reference: https://github.com/yanncam/ShuckNT
        $string7 = /ShuckNT\-main/ nocase ascii wide
        // Description: ShuckNT is the script of Shuck.sh online service for on-premise use. It is design to dowgrade - convert - dissect and shuck authentication token based on Data Encryption Standard (DES)
        // Reference: https://github.com/yanncam/ShuckNT
        $string8 = /wordlist\-nthash\-reversed/ nocase ascii wide
        // Description: ShuckNT is the script of Shuck.sh online service for on-premise use. It is design to dowgrade - convert - dissect and shuck authentication token based on Data Encryption Standard (DES)
        // Reference: https://github.com/yanncam/ShuckNT
        $string9 = /yanncam\/ShuckNT/ nocase ascii wide

    condition:
        any of them
}

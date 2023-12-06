rule whiskeysamlandfriends
{
    meta:
        description = "Detection patterns for the tool 'whiskeysamlandfriends' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "whiskeysamlandfriends"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string1 = /\s\-\-adfs\-host\s.{0,1000}\s\-\-krb\-key\s.{0,1000}\s\-\-krb\-ticket\s/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string2 = /\s\-\-target\-user\s.{0,1000}\s\-\-dc\-ip\s.{0,1000}\s\-command\s/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string3 = /\sticketsplease\./ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string4 = /\/shocknawe\// nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string5 = /\/ticketer\.py/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string6 = /\/ticketsplease\.py/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string7 = /ADFSpoof\.py/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string8 = /dcsync\.py/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string9 = /generate_golden_saml/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string10 = /import\sDCSYNC/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string11 = /shocknawe\.py/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string12 = /smb\.dcsync/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string13 = /ticketsplease\sadfs\s/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string14 = /ticketsplease\sazure\s/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string15 = /ticketsplease\sdcsync\s/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string16 = /ticketsplease\sldap\s/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string17 = /ticketsplease\ssaml\s/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string18 = /ticketsplease\sticket\s\-\-domain/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string19 = /ticketsplease\.modules\./ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string20 = /whiskeysaml\.py/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string21 = /whiskeysamlandfriends/ nocase ascii wide

    condition:
        any of them
}

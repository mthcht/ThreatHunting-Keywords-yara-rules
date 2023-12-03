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
        $string1 = /.{0,1000}\s\-\-adfs\-host\s.{0,1000}\s\-\-krb\-key\s.{0,1000}\s\-\-krb\-ticket\s.{0,1000}/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string2 = /.{0,1000}\s\-\-target\-user\s.{0,1000}\s\-\-dc\-ip\s.{0,1000}\s\-command\s.{0,1000}/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string3 = /.{0,1000}\sticketsplease\..{0,1000}/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string4 = /.{0,1000}\/shocknawe\/.{0,1000}/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string5 = /.{0,1000}\/ticketer\.py.{0,1000}/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string6 = /.{0,1000}\/ticketsplease\.py.{0,1000}/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string7 = /.{0,1000}ADFSpoof\.py.{0,1000}/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string8 = /.{0,1000}dcsync\.py.{0,1000}/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string9 = /.{0,1000}generate_golden_saml.{0,1000}/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string10 = /.{0,1000}import\sDCSYNC.{0,1000}/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string11 = /.{0,1000}shocknawe\.py.{0,1000}/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string12 = /.{0,1000}smb\.dcsync.{0,1000}/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string13 = /.{0,1000}ticketsplease\sadfs\s.{0,1000}/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string14 = /.{0,1000}ticketsplease\sazure\s.{0,1000}/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string15 = /.{0,1000}ticketsplease\sdcsync\s.{0,1000}/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string16 = /.{0,1000}ticketsplease\sldap\s.{0,1000}/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string17 = /.{0,1000}ticketsplease\ssaml\s.{0,1000}/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string18 = /.{0,1000}ticketsplease\sticket\s\-\-domain.{0,1000}/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string19 = /.{0,1000}ticketsplease\.modules\..{0,1000}/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string20 = /.{0,1000}whiskeysaml\.py.{0,1000}/ nocase ascii wide
        // Description: GoldenSAML Attack Libraries and Framework
        // Reference: https://github.com/secureworks/whiskeysamlandfriends
        $string21 = /.{0,1000}whiskeysamlandfriends.{0,1000}/ nocase ascii wide

    condition:
        any of them
}

rule spellbound
{
    meta:
        description = "Detection patterns for the tool 'spellbound' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "spellbound"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Spellbound is a C2 (Command and Control) framework meant for creating a botnet. 
        // Reference: https://github.com/mhuzaifi0604/spellbound
        $string1 = /.{0,1000}\sspellgen\.py\s.{0,1000}/ nocase ascii wide
        // Description: Spellbound is a C2 (Command and Control) framework meant for creating a botnet. 
        // Reference: https://github.com/mhuzaifi0604/spellbound
        $string2 = /.{0,1000}\sspellstager\.py\s.{0,1000}/ nocase ascii wide
        // Description: Spellbound is a C2 (Command and Control) framework meant for creating a botnet. 
        // Reference: https://github.com/mhuzaifi0604/spellbound
        $string3 = /.{0,1000}\/spellbound\.git.{0,1000}/ nocase ascii wide
        // Description: Spellbound is a C2 (Command and Control) framework meant for creating a botnet. 
        // Reference: https://github.com/mhuzaifi0604/spellbound
        $string4 = /.{0,1000}\/spellgen\.py\s.{0,1000}/ nocase ascii wide
        // Description: Spellbound is a C2 (Command and Control) framework meant for creating a botnet. 
        // Reference: https://github.com/mhuzaifi0604/spellbound
        $string5 = /.{0,1000}\/spellstager\.py\s.{0,1000}/ nocase ascii wide
        // Description: Spellbound is a C2 (Command and Control) framework meant for creating a botnet. 
        // Reference: https://github.com/mhuzaifi0604/spellbound
        $string6 = /.{0,1000}\\spellbound\-main.{0,1000}/ nocase ascii wide
        // Description: Spellbound is a C2 (Command and Control) framework meant for creating a botnet. 
        // Reference: https://github.com/mhuzaifi0604/spellbound
        $string7 = /.{0,1000}\\spellgen\.py\s.{0,1000}/ nocase ascii wide
        // Description: Spellbound is a C2 (Command and Control) framework meant for creating a botnet. 
        // Reference: https://github.com/mhuzaifi0604/spellbound
        $string8 = /.{0,1000}\\spellstager\.py\s.{0,1000}/ nocase ascii wide
        // Description: Spellbound is a C2 (Command and Control) framework meant for creating a botnet. 
        // Reference: https://github.com/mhuzaifi0604/spellbound
        $string9 = /.{0,1000}5dec1cfe7c0c2ec55c17fb44b43f7d14.{0,1000}/ nocase ascii wide
        // Description: Spellbound is a C2 (Command and Control) framework meant for creating a botnet. 
        // Reference: https://github.com/mhuzaifi0604/spellbound
        $string10 = /.{0,1000}mhuzaifi0604\/spellbound.{0,1000}/ nocase ascii wide
        // Description: Spellbound is a C2 (Command and Control) framework meant for creating a botnet. 
        // Reference: https://github.com/mhuzaifi0604/spellbound
        $string11 = /.{0,1000}payload_msf\.c.{0,1000}/ nocase ascii wide
        // Description: Spellbound is a C2 (Command and Control) framework meant for creating a botnet. 
        // Reference: https://github.com/mhuzaifi0604/spellbound
        $string12 = /.{0,1000}payload_msf\.exe.{0,1000}/ nocase ascii wide
        // Description: Spellbound is a C2 (Command and Control) framework meant for creating a botnet. 
        // Reference: https://github.com/mhuzaifi0604/spellbound
        $string13 = /.{0,1000}payload_spellshell\.c.{0,1000}/ nocase ascii wide
        // Description: Spellbound is a C2 (Command and Control) framework meant for creating a botnet. 
        // Reference: https://github.com/mhuzaifi0604/spellbound
        $string14 = /.{0,1000}payload_spellshell\.exe.{0,1000}/ nocase ascii wide

    condition:
        any of them
}

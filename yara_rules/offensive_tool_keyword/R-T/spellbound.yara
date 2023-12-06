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
        $string1 = /\sspellgen\.py\s/ nocase ascii wide
        // Description: Spellbound is a C2 (Command and Control) framework meant for creating a botnet. 
        // Reference: https://github.com/mhuzaifi0604/spellbound
        $string2 = /\sspellstager\.py\s/ nocase ascii wide
        // Description: Spellbound is a C2 (Command and Control) framework meant for creating a botnet. 
        // Reference: https://github.com/mhuzaifi0604/spellbound
        $string3 = /\/spellbound\.git/ nocase ascii wide
        // Description: Spellbound is a C2 (Command and Control) framework meant for creating a botnet. 
        // Reference: https://github.com/mhuzaifi0604/spellbound
        $string4 = /\/spellgen\.py\s/ nocase ascii wide
        // Description: Spellbound is a C2 (Command and Control) framework meant for creating a botnet. 
        // Reference: https://github.com/mhuzaifi0604/spellbound
        $string5 = /\/spellstager\.py\s/ nocase ascii wide
        // Description: Spellbound is a C2 (Command and Control) framework meant for creating a botnet. 
        // Reference: https://github.com/mhuzaifi0604/spellbound
        $string6 = /\\spellbound\-main/ nocase ascii wide
        // Description: Spellbound is a C2 (Command and Control) framework meant for creating a botnet. 
        // Reference: https://github.com/mhuzaifi0604/spellbound
        $string7 = /\\spellgen\.py\s/ nocase ascii wide
        // Description: Spellbound is a C2 (Command and Control) framework meant for creating a botnet. 
        // Reference: https://github.com/mhuzaifi0604/spellbound
        $string8 = /\\spellstager\.py\s/ nocase ascii wide
        // Description: Spellbound is a C2 (Command and Control) framework meant for creating a botnet. 
        // Reference: https://github.com/mhuzaifi0604/spellbound
        $string9 = /5dec1cfe7c0c2ec55c17fb44b43f7d14/ nocase ascii wide
        // Description: Spellbound is a C2 (Command and Control) framework meant for creating a botnet. 
        // Reference: https://github.com/mhuzaifi0604/spellbound
        $string10 = /mhuzaifi0604\/spellbound/ nocase ascii wide
        // Description: Spellbound is a C2 (Command and Control) framework meant for creating a botnet. 
        // Reference: https://github.com/mhuzaifi0604/spellbound
        $string11 = /payload_msf\.c/ nocase ascii wide
        // Description: Spellbound is a C2 (Command and Control) framework meant for creating a botnet. 
        // Reference: https://github.com/mhuzaifi0604/spellbound
        $string12 = /payload_msf\.exe/ nocase ascii wide
        // Description: Spellbound is a C2 (Command and Control) framework meant for creating a botnet. 
        // Reference: https://github.com/mhuzaifi0604/spellbound
        $string13 = /payload_spellshell\.c/ nocase ascii wide
        // Description: Spellbound is a C2 (Command and Control) framework meant for creating a botnet. 
        // Reference: https://github.com/mhuzaifi0604/spellbound
        $string14 = /payload_spellshell\.exe/ nocase ascii wide

    condition:
        any of them
}

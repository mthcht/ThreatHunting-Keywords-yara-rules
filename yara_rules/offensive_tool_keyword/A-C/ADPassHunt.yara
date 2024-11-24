rule ADPassHunt
{
    meta:
        description = "Detection patterns for the tool 'ADPassHunt' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ADPassHunt"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: credential stealer tool that hunts Active Directory credentials (leaked tool Developed In-house for Fireeyes Red Team)
        // Reference: https://www.virustotal.com/gui/file/73233ca7230fb5848e220723caa06d795a14c0f1f42c6a59482e812bfb8c217f
        $string1 = /\sADPassHunt\.GetGPPPassword/ nocase ascii wide
        // Description: credential stealer tool that hunts Active Directory credentials (leaked tool Developed In-house for Fireeyes Red Team)
        // Reference: https://www.virustotal.com/gui/file/73233ca7230fb5848e220723caa06d795a14c0f1f42c6a59482e812bfb8c217f
        $string2 = /\[ADA\]\sSearching\sfor\saccounts\swith\smsSFU30Password\sattribute/ nocase ascii wide
        // Description: credential stealer tool that hunts Active Directory credentials (leaked tool Developed In-house for Fireeyes Red Team)
        // Reference: https://www.virustotal.com/gui/file/73233ca7230fb5848e220723caa06d795a14c0f1f42c6a59482e812bfb8c217f
        $string3 = /\[ADA\]\sSearching\sfor\saccounts\swith\suserpassword\sattribute/ nocase ascii wide
        // Description: credential stealer tool that hunts Active Directory credentials (leaked tool Developed In-house for Fireeyes Red Team)
        // Reference: https://www.virustotal.com/gui/file/73233ca7230fb5848e220723caa06d795a14c0f1f42c6a59482e812bfb8c217f
        $string4 = /\[GPP\]\sSearching\sfor\spasswords\snow/ nocase ascii wide
        // Description: credential stealer tool that hunts Active Directory credentials (leaked tool Developed In-house for Fireeyes Red Team)
        // Reference: https://www.virustotal.com/gui/file/73233ca7230fb5848e220723caa06d795a14c0f1f42c6a59482e812bfb8c217f
        $string5 = /\\ADPassHunt\.pdb/ nocase ascii wide
        // Description: credential stealer tool that hunts Active Directory credentials (leaked tool Developed In-house for Fireeyes Red Team)
        // Reference: https://www.virustotal.com/gui/file/73233ca7230fb5848e220723caa06d795a14c0f1f42c6a59482e812bfb8c217f
        $string6 = /\\ADPassHunt\\/ nocase ascii wide
        // Description: credential stealer tool that hunts Active Directory credentials (leaked tool Developed In-house for Fireeyes Red Team)
        // Reference: https://www.virustotal.com/gui/file/73233ca7230fb5848e220723caa06d795a14c0f1f42c6a59482e812bfb8c217f
        $string7 = ">ADPassHunt<" nocase ascii wide
        // Description: credential stealer tool that hunts Active Directory credentials (leaked tool Developed In-house for Fireeyes Red Team)
        // Reference: https://www.virustotal.com/gui/file/73233ca7230fb5848e220723caa06d795a14c0f1f42c6a59482e812bfb8c217f
        $string8 = "73233ca7230fb5848e220723caa06d795a14c0f1f42c6a59482e812bfb8c217f" nocase ascii wide
        // Description: credential stealer tool that hunts Active Directory credentials (leaked tool Developed In-house for Fireeyes Red Team)
        // Reference: https://www.virustotal.com/gui/file/73233ca7230fb5848e220723caa06d795a14c0f1f42c6a59482e812bfb8c217f
        $string9 = /AdPassHunt\s\(PUA\)/ nocase ascii wide
        // Description: credential stealer tool that hunts Active Directory credentials (leaked tool Developed In-house for Fireeyes Red Team)
        // Reference: https://www.virustotal.com/gui/file/73233ca7230fb5848e220723caa06d795a14c0f1f42c6a59482e812bfb8c217f
        $string10 = /ADPassHunt\.exe/ nocase ascii wide
        // Description: credential stealer tool that hunts Active Directory credentials (leaked tool Developed In-house for Fireeyes Red Team)
        // Reference: https://www.virustotal.com/gui/file/73233ca7230fb5848e220723caa06d795a14c0f1f42c6a59482e812bfb8c217f
        $string11 = "Get-GPPAutologons" nocase ascii wide
        // Description: credential stealer tool that hunts Active Directory credentials (leaked tool Developed In-house for Fireeyes Red Team)
        // Reference: https://www.virustotal.com/gui/file/73233ca7230fb5848e220723caa06d795a14c0f1f42c6a59482e812bfb8c217f
        $string12 = "Get-GPPPasswords" nocase ascii wide
        // Description: credential stealer tool that hunts Active Directory credentials (leaked tool Developed In-house for Fireeyes Red Team)
        // Reference: https://www.virustotal.com/gui/file/73233ca7230fb5848e220723caa06d795a14c0f1f42c6a59482e812bfb8c217f
        $string13 = "HackTool:Win32/PWDump" nocase ascii wide
        // Description: credential stealer tool that hunts Active Directory credentials (leaked tool Developed In-house for Fireeyes Red Team)
        // Reference: https://www.virustotal.com/gui/file/73233ca7230fb5848e220723caa06d795a14c0f1f42c6a59482e812bfb8c217f
        $string14 = "HackTool:Win32/PWDump" nocase ascii wide
        // Description: credential stealer tool that hunts Active Directory credentials (leaked tool Developed In-house for Fireeyes Red Team)
        // Reference: https://www.virustotal.com/gui/file/73233ca7230fb5848e220723caa06d795a14c0f1f42c6a59482e812bfb8c217f
        $string15 = /Win\.Tool\.ADPassHunt\-/ nocase ascii wide

    condition:
        any of them
}

rule MAAD_AF
{
    meta:
        description = "Detection patterns for the tool 'MAAD-AF' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MAAD-AF"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string1 = /\/MAAD\-AF\.git/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string2 = /\\Tor\\tor\.exe/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string3 = /\\Tor\\torrc/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string4 = /\\TorBrowser/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string5 = /AzureADRecon\.ps1/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string6 = /Brute\-force\sUnsuccessful\!/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string7 = /BruteForce\.ps1/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string8 = /CrossTenantSynchronizationBackdoor\.ps1/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string9 = /\-\-defaults\-torrc/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string10 = /DisableAntiPhishing/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string11 = /DisableAntiPhishing\.ps1/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string12 = /DisableMailboxAuditing\.ps1/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string13 = /DisableMFA\.ps1/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string14 = /ExternalRecon\.ps1/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string15 = /GrantMailboxAccess\.ps1/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string16 = /Initial_Access\.ps1/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string17 = /LaunchExploitMode\.ps1/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string18 = /LaunchPreCompromise\.ps1/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string19 = /MAAD_Attack\.ps1/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string20 = /MAAD_Config\.ps1/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string21 = /MAAD_Mitre_Map\.ps1/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string22 = /MAADInitialization\.ps1/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string23 = /NewAdminAccountCreation\.ps1/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string24 = /ReconUserGroupRoles\.ps1/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string25 = /SharepointExploiter\.ps1/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string26 = /SharepointSiteExploiter\.ps1/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string27 = /Successfully\scracked\saccount\spassword/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string28 = /TORAnonymizer\.ps1/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string29 = /vectra\-ai\-research\/MAAD\-AF/ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}

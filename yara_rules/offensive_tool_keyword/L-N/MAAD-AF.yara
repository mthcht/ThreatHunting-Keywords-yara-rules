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
        $string1 = /.{0,1000}\/MAAD\-AF\.git.{0,1000}/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string2 = /.{0,1000}\\Tor\\tor\.exe.{0,1000}/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string3 = /.{0,1000}\\Tor\\torrc.{0,1000}/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string4 = /.{0,1000}\\TorBrowser.{0,1000}/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string5 = /.{0,1000}AzureADRecon\.ps1.{0,1000}/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string6 = /.{0,1000}Brute\-force\sUnsuccessful\!.{0,1000}/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string7 = /.{0,1000}BruteForce\.ps1.{0,1000}/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string8 = /.{0,1000}CrossTenantSynchronizationBackdoor\.ps1.{0,1000}/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string9 = /.{0,1000}\-\-defaults\-torrc.{0,1000}/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string10 = /.{0,1000}DisableAntiPhishing.{0,1000}/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string11 = /.{0,1000}DisableAntiPhishing\.ps1.{0,1000}/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string12 = /.{0,1000}DisableMailboxAuditing\.ps1.{0,1000}/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string13 = /.{0,1000}DisableMFA\.ps1.{0,1000}/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string14 = /.{0,1000}ExternalRecon\.ps1.{0,1000}/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string15 = /.{0,1000}GrantMailboxAccess\.ps1.{0,1000}/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string16 = /.{0,1000}Initial_Access\.ps1.{0,1000}/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string17 = /.{0,1000}LaunchExploitMode\.ps1.{0,1000}/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string18 = /.{0,1000}LaunchPreCompromise\.ps1.{0,1000}/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string19 = /.{0,1000}MAAD_Attack\.ps1.{0,1000}/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string20 = /.{0,1000}MAAD_Config\.ps1.{0,1000}/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string21 = /.{0,1000}MAAD_Mitre_Map\.ps1.{0,1000}/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string22 = /.{0,1000}MAADInitialization\.ps1.{0,1000}/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string23 = /.{0,1000}NewAdminAccountCreation\.ps1.{0,1000}/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string24 = /.{0,1000}ReconUserGroupRoles\.ps1.{0,1000}/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string25 = /.{0,1000}SharepointExploiter\.ps1.{0,1000}/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string26 = /.{0,1000}SharepointSiteExploiter\.ps1.{0,1000}/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string27 = /.{0,1000}Successfully\scracked\saccount\spassword.{0,1000}/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string28 = /.{0,1000}TORAnonymizer\.ps1.{0,1000}/ nocase ascii wide
        // Description: MAAD Attack Framework - An attack tool for simple fast & effective security testing of M365 & Azure AD. 
        // Reference: https://github.com/vectra-ai-research/MAAD-AF
        $string29 = /.{0,1000}vectra\-ai\-research\/MAAD\-AF.{0,1000}/ nocase ascii wide

    condition:
        any of them
}

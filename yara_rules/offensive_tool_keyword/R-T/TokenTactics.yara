rule TokenTactics
{
    meta:
        description = "Detection patterns for the tool 'TokenTactics' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TokenTactics"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Azure JWT Token Manipulation Toolset
        // Reference: https://github.com/rvrsh3ll/TokenTactics
        $string1 = /\/CapBypass\.ps1/ nocase ascii wide
        // Description: Azure JWT Token Manipulation Toolset
        // Reference: https://github.com/rvrsh3ll/TokenTactics
        $string2 = /\/rvrsh3ll\// nocase ascii wide
        // Description: Azure JWT Token Manipulation Toolset
        // Reference: https://github.com/rvrsh3ll/TokenTactics
        $string3 = /\/TokenTactics\.git/ nocase ascii wide
        // Description: Azure JWT Token Manipulation Toolset
        // Reference: https://github.com/rvrsh3ll/TokenTactics
        $string4 = /capturetokenphish\.ps1/ nocase ascii wide
        // Description: Azure JWT Token Manipulation Toolset
        // Reference: https://github.com/rvrsh3ll/TokenTactics
        $string5 = /capturetokenphish\.py/ nocase ascii wide
        // Description: Azure JWT Token Manipulation Toolset
        // Reference: https://github.com/rvrsh3ll/TokenTactics
        $string6 = /Connect\-AzureAD\s\-AadAccessToken\s\-AccountId\s/ nocase ascii wide
        // Description: Azure JWT Token Manipulation Toolset
        // Reference: https://github.com/rvrsh3ll/TokenTactics
        $string7 = /deploycaptureserver\.ps1/ nocase ascii wide
        // Description: Azure JWT Token Manipulation Toolset
        // Reference: https://github.com/rvrsh3ll/TokenTactics
        $string8 = /Invoke\-DumpOWAMailboxViaMSGraphApi/ nocase ascii wide
        // Description: Azure JWT Token Manipulation Toolset
        // Reference: https://github.com/rvrsh3ll/TokenTactics
        $string9 = /Invoke\-ForgeUserAgent/ nocase ascii wide
        // Description: Azure JWT Token Manipulation Toolset
        // Reference: https://github.com/rvrsh3ll/TokenTactics
        $string10 = /Invoke\-OpenOWAMailboxInBrowser/ nocase ascii wide
        // Description: Azure JWT Token Manipulation Toolset
        // Reference: https://github.com/rvrsh3ll/TokenTactics
        $string11 = /Invoke\-RefreshToMSGraphToken\s\-domain\s\-ClientId\s/ nocase ascii wide
        // Description: Azure JWT Token Manipulation Toolset
        // Reference: https://github.com/rvrsh3ll/TokenTactics
        $string12 = /OutlookEmailAbuse\.ps1/ nocase ascii wide
        // Description: Azure JWT Token Manipulation Toolset
        // Reference: https://github.com/rvrsh3ll/TokenTactics
        $string13 = /rvrsh3ll\/TokenTactics/ nocase ascii wide
        // Description: Azure JWT Token Manipulation Toolset
        // Reference: https://github.com/rvrsh3ll/TokenTactics
        $string14 = /TokenTactics\.psd1/ nocase ascii wide
        // Description: Azure JWT Token Manipulation Toolset
        // Reference: https://github.com/rvrsh3ll/TokenTactics
        $string15 = /TokenTactics\.psm1/ nocase ascii wide
        // Description: Azure JWT Token Manipulation Toolset
        // Reference: https://github.com/rvrsh3ll/TokenTactics
        $string16 = /TokenTactics\-main\.zip/ nocase ascii wide

    condition:
        any of them
}

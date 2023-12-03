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
        $string1 = /.{0,1000}\/CapBypass\.ps1.{0,1000}/ nocase ascii wide
        // Description: Azure JWT Token Manipulation Toolset
        // Reference: https://github.com/rvrsh3ll/TokenTactics
        $string2 = /.{0,1000}\/rvrsh3ll\/.{0,1000}/ nocase ascii wide
        // Description: Azure JWT Token Manipulation Toolset
        // Reference: https://github.com/rvrsh3ll/TokenTactics
        $string3 = /.{0,1000}\/TokenTactics\.git.{0,1000}/ nocase ascii wide
        // Description: Azure JWT Token Manipulation Toolset
        // Reference: https://github.com/rvrsh3ll/TokenTactics
        $string4 = /.{0,1000}capturetokenphish\.ps1.{0,1000}/ nocase ascii wide
        // Description: Azure JWT Token Manipulation Toolset
        // Reference: https://github.com/rvrsh3ll/TokenTactics
        $string5 = /.{0,1000}capturetokenphish\.py.{0,1000}/ nocase ascii wide
        // Description: Azure JWT Token Manipulation Toolset
        // Reference: https://github.com/rvrsh3ll/TokenTactics
        $string6 = /.{0,1000}Connect\-AzureAD\s\-AadAccessToken\s\-AccountId\s.{0,1000}/ nocase ascii wide
        // Description: Azure JWT Token Manipulation Toolset
        // Reference: https://github.com/rvrsh3ll/TokenTactics
        $string7 = /.{0,1000}deploycaptureserver\.ps1.{0,1000}/ nocase ascii wide
        // Description: Azure JWT Token Manipulation Toolset
        // Reference: https://github.com/rvrsh3ll/TokenTactics
        $string8 = /.{0,1000}Invoke\-DumpOWAMailboxViaMSGraphApi.{0,1000}/ nocase ascii wide
        // Description: Azure JWT Token Manipulation Toolset
        // Reference: https://github.com/rvrsh3ll/TokenTactics
        $string9 = /.{0,1000}Invoke\-ForgeUserAgent.{0,1000}/ nocase ascii wide
        // Description: Azure JWT Token Manipulation Toolset
        // Reference: https://github.com/rvrsh3ll/TokenTactics
        $string10 = /.{0,1000}Invoke\-OpenOWAMailboxInBrowser.{0,1000}/ nocase ascii wide
        // Description: Azure JWT Token Manipulation Toolset
        // Reference: https://github.com/rvrsh3ll/TokenTactics
        $string11 = /.{0,1000}Invoke\-RefreshToMSGraphToken\s\-domain\s\-ClientId\s.{0,1000}/ nocase ascii wide
        // Description: Azure JWT Token Manipulation Toolset
        // Reference: https://github.com/rvrsh3ll/TokenTactics
        $string12 = /.{0,1000}OutlookEmailAbuse\.ps1.{0,1000}/ nocase ascii wide
        // Description: Azure JWT Token Manipulation Toolset
        // Reference: https://github.com/rvrsh3ll/TokenTactics
        $string13 = /.{0,1000}rvrsh3ll\/TokenTactics.{0,1000}/ nocase ascii wide
        // Description: Azure JWT Token Manipulation Toolset
        // Reference: https://github.com/rvrsh3ll/TokenTactics
        $string14 = /.{0,1000}TokenTactics\.psd1.{0,1000}/ nocase ascii wide
        // Description: Azure JWT Token Manipulation Toolset
        // Reference: https://github.com/rvrsh3ll/TokenTactics
        $string15 = /.{0,1000}TokenTactics\.psm1.{0,1000}/ nocase ascii wide
        // Description: Azure JWT Token Manipulation Toolset
        // Reference: https://github.com/rvrsh3ll/TokenTactics
        $string16 = /.{0,1000}TokenTactics\-main\.zip.{0,1000}/ nocase ascii wide

    condition:
        any of them
}

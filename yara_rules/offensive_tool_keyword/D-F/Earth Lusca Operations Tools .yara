rule Earth_Lusca_Operations_Tools_
{
    meta:
        description = "Detection patterns for the tool 'Earth Lusca Operations Tools ' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Earth Lusca Operations Tools "
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf https://github.com/BeichenDream/BadPotato
        $string1 = /.{0,1000}BadPotato\.cs.{0,1000}/ nocase ascii wide
        // Description: Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf https://github.com/BeichenDream/BadPotato
        $string2 = /.{0,1000}badpotato\.exe.{0,1000}/ nocase ascii wide
        // Description: Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf https://github.com/winscripting/UAC-bypass/blob/master/FodhelperBypass.ps1
        $string3 = /.{0,1000}fodhelperUACBypass.{0,1000}/ nocase ascii wide
        // Description: Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf https://github.com/RickGeex/ProxyLogon
        $string4 = /.{0,1000}proxyLogon\.py.{0,1000}/ nocase ascii wide
        // Description: Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf https://github.com/dmaasland/proxyshell-poc
        $string5 = /.{0,1000}proxyshell\.py.{0,1000}/ nocase ascii wide
        // Description: Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf https://github.com/dmaasland/proxyshell-poc
        $string6 = /.{0,1000}proxyshell_rce\.py.{0,1000}/ nocase ascii wide
        // Description: Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf https://github.com/dmaasland/proxyshell-poc
        $string7 = /.{0,1000}proxyshell\-enumerate\.py.{0,1000}/ nocase ascii wide
        // Description: Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf https://github.com/dmaasland/proxyshell-poc
        $string8 = /.{0,1000}proxyshell\-poc.{0,1000}/ nocase ascii wide
        // Description: Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf https://github.com/winscripting/UAC-bypass/blob/master/FodhelperBypass.ps1
        $string9 = /.{0,1000}UAC\-bypass.{0,1000}/ nocase ascii wide

    condition:
        any of them
}

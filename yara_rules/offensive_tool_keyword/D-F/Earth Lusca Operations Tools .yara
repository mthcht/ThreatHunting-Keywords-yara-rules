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
        $string1 = /BadPotato\.cs/ nocase ascii wide
        // Description: Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf https://github.com/BeichenDream/BadPotato
        $string2 = /badpotato\.exe/ nocase ascii wide
        // Description: Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf https://github.com/winscripting/UAC-bypass/blob/master/FodhelperBypass.ps1
        $string3 = /fodhelperUACBypass/ nocase ascii wide
        // Description: Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf https://github.com/RickGeex/ProxyLogon
        $string4 = /proxyLogon\.py/ nocase ascii wide
        // Description: Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf https://github.com/dmaasland/proxyshell-poc
        $string5 = /proxyshell\.py/ nocase ascii wide
        // Description: Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf https://github.com/dmaasland/proxyshell-poc
        $string6 = /proxyshell_rce\.py/ nocase ascii wide
        // Description: Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf https://github.com/dmaasland/proxyshell-poc
        $string7 = /proxyshell\-enumerate\.py/ nocase ascii wide
        // Description: Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf https://github.com/dmaasland/proxyshell-poc
        $string8 = /proxyshell\-poc/ nocase ascii wide
        // Description: Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf https://github.com/winscripting/UAC-bypass/blob/master/FodhelperBypass.ps1
        $string9 = /UAC\-bypass/ nocase ascii wide

    condition:
        any of them
}

rule pingcastle
{
    meta:
        description = "Detection patterns for the tool 'pingcastle' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pingcastle"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: active directory weakness scan Vulnerability scanner and Earth Lusca Operations Tools and commands
        // Reference: https://github.com/sense-of-security/ADRecon
        $string1 = /\/ADRecon/ nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner and Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf https://github.com/vletoux/pingcastle
        $string2 = /ACLScanner\.exe/ nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner and Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf https://github.com/vletoux/pingcastle
        $string3 = /bluekeepscanner\.exe/ nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner and Earth Lusca Operations Tools and commands
        // Reference: https://github.com/vletoux/pingcastle
        $string4 = /NullSessionScanner\./ nocase ascii wide
        // Description: active directory weakness scan
        // Reference: https://www.pingcastle.com/
        $string5 = /pingcastle/ nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner and Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf https://github.com/vletoux/pingcastle
        $string6 = /PingCastle\.cs/ nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner and Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf https://github.com/vletoux/pingcastle
        $string7 = /PingCastle\.exe/ nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner and Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf https://github.com/vletoux/pingcastle
        $string8 = /RemoteScanner\.exe/ nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner and Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf https://github.com/vletoux/pingcastle
        $string9 = /ROCAVulnerabilityTester/ nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner and Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf https://github.com/vletoux/pingcastle
        $string10 = /SmbScanner\.exe/ nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner and Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf https://github.com/vletoux/pingcastle
        $string11 = /ZeroLogonScanner\./ nocase ascii wide

    condition:
        any of them
}

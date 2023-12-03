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
        $string1 = /.{0,1000}\/ADRecon.{0,1000}/ nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner and Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf https://github.com/vletoux/pingcastle
        $string2 = /.{0,1000}ACLScanner\.exe.{0,1000}/ nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner and Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf https://github.com/vletoux/pingcastle
        $string3 = /.{0,1000}bluekeepscanner\.exe.{0,1000}/ nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner and Earth Lusca Operations Tools and commands
        // Reference: https://github.com/vletoux/pingcastle
        $string4 = /.{0,1000}NullSessionScanner\..{0,1000}/ nocase ascii wide
        // Description: active directory weakness scan
        // Reference: https://www.pingcastle.com/
        $string5 = /.{0,1000}pingcastle.{0,1000}/ nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner and Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf https://github.com/vletoux/pingcastle
        $string6 = /.{0,1000}PingCastle\.cs.{0,1000}/ nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner and Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf https://github.com/vletoux/pingcastle
        $string7 = /.{0,1000}PingCastle\.exe.{0,1000}/ nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner and Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf https://github.com/vletoux/pingcastle
        $string8 = /.{0,1000}RemoteScanner\.exe.{0,1000}/ nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner and Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf https://github.com/vletoux/pingcastle
        $string9 = /.{0,1000}ROCAVulnerabilityTester.{0,1000}/ nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner and Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf https://github.com/vletoux/pingcastle
        $string10 = /.{0,1000}SmbScanner\.exe.{0,1000}/ nocase ascii wide
        // Description: active directory weakness scan Vulnerability scanner and Earth Lusca Operations Tools and commands
        // Reference: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf https://github.com/vletoux/pingcastle
        $string11 = /.{0,1000}ZeroLogonScanner\..{0,1000}/ nocase ascii wide

    condition:
        any of them
}

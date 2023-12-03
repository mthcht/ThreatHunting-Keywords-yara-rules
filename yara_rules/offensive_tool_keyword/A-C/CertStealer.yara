rule CertStealer
{
    meta:
        description = "Detection patterns for the tool 'CertStealer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CertStealer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A .NET tool for exporting and importing certificates without touching disk.
        // Reference: https://github.com/TheWover/CertStealer
        $string1 = /.{0,1000}\/CertStealer.{0,1000}/ nocase ascii wide
        // Description: A .NET tool for exporting and importing certificates without touching disk.
        // Reference: https://github.com/TheWover/CertStealer
        $string2 = /.{0,1000}CertStealer\.csproj.{0,1000}/ nocase ascii wide
        // Description: A .NET tool for exporting and importing certificates without touching disk.
        // Reference: https://github.com/TheWover/CertStealer
        $string3 = /.{0,1000}CertStealer\.exe.{0,1000}/ nocase ascii wide
        // Description: A .NET tool for exporting and importing certificates without touching disk.
        // Reference: https://github.com/TheWover/CertStealer
        $string4 = /.{0,1000}CertStealer\.sln.{0,1000}/ nocase ascii wide

    condition:
        any of them
}

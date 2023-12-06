rule SMBetray
{
    meta:
        description = "Detection patterns for the tool 'SMBetray' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SMBetray"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PoC to demonstrate the ability of an attacker to intercept and modify insecure SMB connections. as well as compromise some secured SMB connections if credentials are known.
        // Reference: https://github.com/quickbreach/SMBetray
        $string1 = /SMBetray/ nocase ascii wide

    condition:
        any of them
}

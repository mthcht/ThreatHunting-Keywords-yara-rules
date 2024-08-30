rule BITSInject
{
    meta:
        description = "Detection patterns for the tool 'BITSInject' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BITSInject"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A one-click tool to inject jobs into the BITS queue (Background Intelligent Transfer Service) allowing arbitrary program execution as the NT AUTHORITY/SYSTEM account
        // Reference: https://github.com/SafeBreach-Labs/BITSInject
        $string1 = /\sBITSInject\.py/ nocase ascii wide
        // Description: A one-click tool to inject jobs into the BITS queue (Background Intelligent Transfer Service) allowing arbitrary program execution as the NT AUTHORITY/SYSTEM account
        // Reference: https://github.com/SafeBreach-Labs/BITSInject
        $string2 = /\sBITSJobPayloads\.py/ nocase ascii wide
        // Description: A one-click tool to inject jobs into the BITS queue (Background Intelligent Transfer Service) allowing arbitrary program execution as the NT AUTHORITY/SYSTEM account
        // Reference: https://github.com/SafeBreach-Labs/BITSInject
        $string3 = /\/BITSInject\.git/ nocase ascii wide
        // Description: A one-click tool to inject jobs into the BITS queue (Background Intelligent Transfer Service) allowing arbitrary program execution as the NT AUTHORITY/SYSTEM account
        // Reference: https://github.com/SafeBreach-Labs/BITSInject
        $string4 = /\/BITSInject\.py/ nocase ascii wide
        // Description: A one-click tool to inject jobs into the BITS queue (Background Intelligent Transfer Service) allowing arbitrary program execution as the NT AUTHORITY/SYSTEM account
        // Reference: https://github.com/SafeBreach-Labs/BITSInject
        $string5 = /\/BITSJobPayloads\.py/ nocase ascii wide
        // Description: A one-click tool to inject jobs into the BITS queue (Background Intelligent Transfer Service) allowing arbitrary program execution as the NT AUTHORITY/SYSTEM account
        // Reference: https://github.com/SafeBreach-Labs/BITSInject
        $string6 = /\\BITSInject\.py/ nocase ascii wide
        // Description: A one-click tool to inject jobs into the BITS queue (Background Intelligent Transfer Service) allowing arbitrary program execution as the NT AUTHORITY/SYSTEM account
        // Reference: https://github.com/SafeBreach-Labs/BITSInject
        $string7 = /\\BITSInject\-master/ nocase ascii wide
        // Description: A one-click tool to inject jobs into the BITS queue (Background Intelligent Transfer Service) allowing arbitrary program execution as the NT AUTHORITY/SYSTEM account
        // Reference: https://github.com/SafeBreach-Labs/BITSInject
        $string8 = /\\BITSJobPayloads\.py/ nocase ascii wide
        // Description: A one-click tool to inject jobs into the BITS queue (Background Intelligent Transfer Service) allowing arbitrary program execution as the NT AUTHORITY/SYSTEM account
        // Reference: https://github.com/SafeBreach-Labs/BITSInject
        $string9 = /09e0c32321b7bc4b6d95f4a36d9030ce2333d67ffff15e4ff51631c3c4aa319d/ nocase ascii wide
        // Description: A one-click tool to inject jobs into the BITS queue (Background Intelligent Transfer Service) allowing arbitrary program execution as the NT AUTHORITY/SYSTEM account
        // Reference: https://github.com/SafeBreach-Labs/BITSInject
        $string10 = /880b020391f6702f07775929110ac0f9aff0cec6fce2bd8e1e079bcace792e33/ nocase ascii wide
        // Description: A one-click tool to inject jobs into the BITS queue (Background Intelligent Transfer Service) allowing arbitrary program execution as the NT AUTHORITY/SYSTEM account
        // Reference: https://github.com/SafeBreach-Labs/BITSInject
        $string11 = /93362035A00C104A84F3B17E7B499CD700000000020000000000000000000000C00A1281B535EF499/ nocase ascii wide
        // Description: A one-click tool to inject jobs into the BITS queue (Background Intelligent Transfer Service) allowing arbitrary program execution as the NT AUTHORITY/SYSTEM account
        // Reference: https://github.com/SafeBreach-Labs/BITSInject
        $string12 = /SafeBreach\-Labs\/BITSInject/ nocase ascii wide

    condition:
        any of them
}

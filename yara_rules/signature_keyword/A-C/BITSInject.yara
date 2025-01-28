rule BITSInject
{
    meta:
        description = "Detection patterns for the tool 'BITSInject' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BITSInject"
        rule_category = "signature_keyword"

    strings:
        // Description: A one-click tool to inject jobs into the BITS queue (Background Intelligent Transfer Service) allowing arbitrary program execution as the NT AUTHORITY/SYSTEM account
        // Reference: https://github.com/SafeBreach-Labs/BITSInject
        $string1 = /Behavior\:Win32\/BitsInject\.A\!attk/ nocase ascii wide

    condition:
        any of them
}

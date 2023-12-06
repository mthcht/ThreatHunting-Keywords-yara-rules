rule Mobile_Security_Framework
{
    meta:
        description = "Detection patterns for the tool 'Mobile-Security-Framework' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Mobile-Security-Framework"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Mobile Security Framework (MobSF) is an automated. all-in-one mobile application (Android/iOS/Windows) pen-testing. malware analysis and security assessment framework capable of performing static and dynamic analysis.
        // Reference: https://github.com/MobSF/Mobile-Security-Framework-MobSF
        $string1 = /Mobile\-Security\-Framework/ nocase ascii wide

    condition:
        any of them
}

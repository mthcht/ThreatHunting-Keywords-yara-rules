rule Mobile_Security_Framework_MobSF
{
    meta:
        description = "Detection patterns for the tool 'Mobile-Security-Framework-MobSF' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Mobile-Security-Framework-MobSF"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Mobile Security Framework (MobSF) is an automated. all-in-one mobile application (Android/iOS/Windows) pen-testing. malware analysis and security assessment framework capable of performing static and dynamic analysis. MobSF support mobile app binaries (APK. XAPK. IPA & APPX) along with zipped source code and provides REST APIs for seamless integration with your CI/CD or DevSecOps pipeline.The Dynamic Analyzer helps you to perform runtime security assessment and interactive instrumented testing.
        // Reference: https://github.com/MobSF/Mobile-Security-Framework-MobSF
        $string1 = /Framework\-MobSF/ nocase ascii wide
        // Description: Mobile Security Framework (MobSF) is an automated. all-in-one mobile application (Android/iOS/Windows) pen-testing. malware analysis and security assessment framework capable of performing static and dynamic analysis.
        // Reference: https://github.com/MobSF/Mobile-Security-Framework-MobSF
        $string2 = /Mobile\-Security\-Framework/ nocase ascii wide

    condition:
        any of them
}

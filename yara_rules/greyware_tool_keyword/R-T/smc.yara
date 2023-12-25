rule smc
{
    meta:
        description = "Detection patterns for the tool 'smc' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "smc"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Symantec Client Management Component or (smc.exe) is a command-line utility that can manage (enable - disable - export) different components of SEP
        // Reference: https://github.com/3CORESec/MAL-CL/tree/master/Descriptors/Antivirus/Symantec%20Endpoint%20Protection#threat-actor-ops-taops
        $string1 = /smc\s\-disable\s\-mem/ nocase ascii wide
        // Description: Symantec Client Management Component or (smc.exe) is a command-line utility that can manage (enable - disable - export) different components of SEP
        // Reference: https://github.com/3CORESec/MAL-CL/tree/master/Descriptors/Antivirus/Symantec%20Endpoint%20Protection#threat-actor-ops-taops
        $string2 = /smc\s\-disable\s\-ntp/ nocase ascii wide
        // Description: Symantec Client Management Component or (smc.exe) is a command-line utility that can manage (enable - disable - export) different components of SEP
        // Reference: https://github.com/3CORESec/MAL-CL/tree/master/Descriptors/Antivirus/Symantec%20Endpoint%20Protection#threat-actor-ops-taops
        $string3 = /smc\s\-disable\s\-wss/ nocase ascii wide
        // Description: Symantec Client Management Component or (smc.exe) is a command-line utility that can manage (enable - disable - export) different components of SEP
        // Reference: https://github.com/3CORESec/MAL-CL/tree/master/Descriptors/Antivirus/Symantec%20Endpoint%20Protection#threat-actor-ops-taops
        $string4 = /smc\s\-enable\s\-gem/ nocase ascii wide
        // Description: Symantec Client Management Component or (smc.exe) is a command-line utility that can manage (enable - disable - export) different components of SEP
        // Reference: https://github.com/3CORESec/MAL-CL/tree/master/Descriptors/Antivirus/Symantec%20Endpoint%20Protection#threat-actor-ops-taops
        $string5 = /smc\.exe\s\-disable\s\-mem/ nocase ascii wide
        // Description: Symantec Client Management Component or (smc.exe) is a command-line utility that can manage (enable - disable - export) different components of SEP
        // Reference: https://github.com/3CORESec/MAL-CL/tree/master/Descriptors/Antivirus/Symantec%20Endpoint%20Protection#threat-actor-ops-taops
        $string6 = /smc\.exe\s\-disable\s\-ntp/ nocase ascii wide
        // Description: Symantec Client Management Component or (smc.exe) is a command-line utility that can manage (enable - disable - export) different components of SEP
        // Reference: https://github.com/3CORESec/MAL-CL/tree/master/Descriptors/Antivirus/Symantec%20Endpoint%20Protection#threat-actor-ops-taops
        $string7 = /smc\.exe\s\-disable\s\-wss/ nocase ascii wide
        // Description: Symantec Client Management Component or (smc.exe) is a command-line utility that can manage (enable - disable - export) different components of SEP
        // Reference: https://github.com/3CORESec/MAL-CL/tree/master/Descriptors/Antivirus/Symantec%20Endpoint%20Protection#threat-actor-ops-taops
        $string8 = /smc\.exe\s\-enable\s\-gem/ nocase ascii wide

    condition:
        any of them
}

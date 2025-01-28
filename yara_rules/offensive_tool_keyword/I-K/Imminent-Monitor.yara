rule Imminent_Monitor
{
    meta:
        description = "Detection patterns for the tool 'Imminent-Monitor' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Imminent-Monitor"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: used for malicious activities such as keylogging - screen capture and remote control of infected systems.
        // Reference: https://github.com/Indestructible7/Imminent-Monitor-v3.9
        $string1 = /\/Imminent\sMonitor\s3\.9\.exe/ nocase ascii wide
        // Description: used for malicious activities such as keylogging - screen capture and remote control of infected systems.
        // Reference: https://github.com/Indestructible7/Imminent-Monitor-v3.9
        $string2 = /\/ImminentMonitor\.exe/ nocase ascii wide
        // Description: used for malicious activities such as keylogging - screen capture and remote control of infected systems.
        // Reference: https://github.com/Indestructible7/Imminent-Monitor-v3.9
        $string3 = /\\Imminent\sMonitor\s3\.9\.exe/ nocase ascii wide
        // Description: used for malicious activities such as keylogging - screen capture and remote control of infected systems.
        // Reference: https://github.com/Indestructible7/Imminent-Monitor-v3.9
        $string4 = /\\ImminentMonitor\.exe/ nocase ascii wide
        // Description: used for malicious activities such as keylogging - screen capture and remote control of infected systems.
        // Reference: https://github.com/Indestructible7/Imminent-Monitor-v3.9
        $string5 = ">Imminent Monitor<" nocase ascii wide
        // Description: used for malicious activities such as keylogging - screen capture and remote control of infected systems.
        // Reference: https://github.com/Indestructible7/Imminent-Monitor-v3.9
        $string6 = "6c7b6faf5a493f036e6b69a0f4c9c7f1b86c068a56ce4d8d9a92c8ebde0eae99" nocase ascii wide
        // Description: used for malicious activities such as keylogging - screen capture and remote control of infected systems.
        // Reference: https://github.com/Indestructible7/Imminent-Monitor-v3.9
        $string7 = "9078149dc6ee62aea91749ba2db9aba15c9518f92bfe709b3bba8523f92cd2e8" nocase ascii wide
        // Description: used for malicious activities such as keylogging - screen capture and remote control of infected systems.
        // Reference: https://github.com/Indestructible7/Imminent-Monitor-v3.9
        $string8 = "Indestructible7/Imminent-Monitor" nocase ascii wide

    condition:
        any of them
}

rule ThunderShell
{
    meta:
        description = "Detection patterns for the tool 'ThunderShell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ThunderShell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: ThunderShell is a C# RAT that communicates via HTTP requests. All the network traffic is encrypted using a second layer of RC4 to avoid SSL interception and defeat network detection on the target system. RC4 is a weak cipher and is used to help obfuscate the traffic. HTTPS options should be used to provide integrity and strong encryption.
        // Reference: https://github.com/Mr-Un1k0d3r/ThunderShell
        $string1 = /data\/payloads\/stager\.ps1/ nocase ascii wide
        // Description: ThunderShell is a C# RAT that communicates via HTTP requests. All the network traffic is encrypted using a second layer of RC4 to avoid SSL interception and defeat network detection on the target system. RC4 is a weak cipher and is used to help obfuscate the traffic. HTTPS options should be used to provide integrity and strong encryption.
        // Reference: https://github.com/Mr-Un1k0d3r/ThunderShell
        $string2 = /mr\.un1k0d3r\@gmail\.com/ nocase ascii wide
        // Description: ThunderShell is a C# RAT that communicates via HTTP requests. All the network traffic is encrypted using a second layer of RC4 to avoid SSL interception and defeat network detection on the target system. RC4 is a weak cipher and is used to help obfuscate the traffic. HTTPS options should be used to provide integrity and strong encryption.
        // Reference: https://github.com/Mr-Un1k0d3r/ThunderShell
        $string3 = /\-out.{0,1000}\.exe\s\-r\:.{0,1000}System\.Drawing\.dll.{0,1000}System\.Management\.Automation.{0,1000}\.dll/ nocase ascii wide
        // Description: ThunderShell is a C# RAT that communicates via HTTP requests. All the network traffic is encrypted using a second layer of RC4 to avoid SSL interception and defeat network detection on the target system. RC4 is a weak cipher and is used to help obfuscate the traffic. HTTPS options should be used to provide integrity and strong encryption.
        // Reference: https://github.com/Mr-Un1k0d3r/ThunderShell
        $string4 = /PppEWCIgXbsepIwnuRIHtQLC/ nocase ascii wide
        // Description: ThunderShell is a C# RAT that communicates via HTTP requests. All the network traffic is encrypted using a second layer of RC4 to avoid SSL interception and defeat network detection on the target system. RC4 is a weak cipher and is used to help obfuscate the traffic. HTTPS options should be used to provide integrity and strong encryption.
        // Reference: https://github.com/Mr-Un1k0d3r/ThunderShell
        $string5 = /scripts.{0,1000}Remote\-WmiExecute\./ nocase ascii wide
        // Description: ThunderShell is a C# RAT that communicates via HTTP requests. All the network traffic is encrypted using a second layer of RC4 to avoid SSL interception and defeat network detection on the target system. RC4 is a weak cipher and is used to help obfuscate the traffic. HTTPS options should be used to provide integrity and strong encryption.
        // Reference: https://github.com/Mr-Un1k0d3r/ThunderShell
        $string6 = /scripts.{0,1000}Search\-EventForUser\.ps1/ nocase ascii wide
        // Description: ThunderShell is a C# RAT that communicates via HTTP requests. All the network traffic is encrypted using a second layer of RC4 to avoid SSL interception and defeat network detection on the target system. RC4 is a weak cipher and is used to help obfuscate the traffic. HTTPS options should be used to provide integrity and strong encryption.
        // Reference: https://github.com/Mr-Un1k0d3r/ThunderShell
        $string7 = /ThunderShell/ nocase ascii wide
        // Description: ThunderShell is a C# RAT that communicates via HTTP requests. All the network traffic is encrypted using a second layer of RC4 to avoid SSL interception and defeat network detection on the target system. RC4 is a weak cipher and is used to help obfuscate the traffic. HTTPS options should be used to provide integrity and strong encryption.
        // Reference: https://github.com/Mr-Un1k0d3r/ThunderShell
        $string8 = /ThunderShell\.git/ nocase ascii wide
        // Description: ThunderShell is a C# RAT that communicates via HTTP requests. All the network traffic is encrypted using a second layer of RC4 to avoid SSL interception and defeat network detection on the target system. RC4 is a weak cipher and is used to help obfuscate the traffic. HTTPS options should be used to provide integrity and strong encryption.
        // Reference: https://github.com/Mr-Un1k0d3r/ThunderShell
        $string9 = /ThunderShell\.py/ nocase ascii wide
        // Description: ThunderShell is a C# RAT that communicates via HTTP requests. All the network traffic is encrypted using a second layer of RC4 to avoid SSL interception and defeat network detection on the target system. RC4 is a weak cipher and is used to help obfuscate the traffic. HTTPS options should be used to provide integrity and strong encryption.
        // Reference: https://github.com/Mr-Un1k0d3r/ThunderShell
        $string10 = /ThunderShell\-master\.zip/ nocase ascii wide
        // Description: ThunderShell is a C# RAT that communicates via HTTP requests. All the network traffic is encrypted using a second layer of RC4 to avoid SSL interception and defeat network detection on the target system. RC4 is a weak cipher and is used to help obfuscate the traffic. HTTPS options should be used to provide integrity and strong encryption.
        // Reference: https://github.com/Mr-Un1k0d3r/ThunderShell
        $string11 = /YaWNdpwplLwycqWQDCyruhAFsYjWjnBA/ nocase ascii wide

    condition:
        any of them
}

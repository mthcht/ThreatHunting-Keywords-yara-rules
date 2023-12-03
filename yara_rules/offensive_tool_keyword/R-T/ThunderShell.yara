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
        $string1 = /.{0,1000}data\/payloads\/stager\.ps1.{0,1000}/ nocase ascii wide
        // Description: ThunderShell is a C# RAT that communicates via HTTP requests. All the network traffic is encrypted using a second layer of RC4 to avoid SSL interception and defeat network detection on the target system. RC4 is a weak cipher and is used to help obfuscate the traffic. HTTPS options should be used to provide integrity and strong encryption.
        // Reference: https://github.com/Mr-Un1k0d3r/ThunderShell
        $string2 = /.{0,1000}mr\.un1k0d3r\@gmail\.com.{0,1000}/ nocase ascii wide
        // Description: ThunderShell is a C# RAT that communicates via HTTP requests. All the network traffic is encrypted using a second layer of RC4 to avoid SSL interception and defeat network detection on the target system. RC4 is a weak cipher and is used to help obfuscate the traffic. HTTPS options should be used to provide integrity and strong encryption.
        // Reference: https://github.com/Mr-Un1k0d3r/ThunderShell
        $string3 = /.{0,1000}\-out.{0,1000}\.exe\s\-r:.{0,1000}System\.Drawing\.dll.{0,1000}System\.Management\.Automation.{0,1000}\.dll.{0,1000}/ nocase ascii wide
        // Description: ThunderShell is a C# RAT that communicates via HTTP requests. All the network traffic is encrypted using a second layer of RC4 to avoid SSL interception and defeat network detection on the target system. RC4 is a weak cipher and is used to help obfuscate the traffic. HTTPS options should be used to provide integrity and strong encryption.
        // Reference: https://github.com/Mr-Un1k0d3r/ThunderShell
        $string4 = /.{0,1000}PppEWCIgXbsepIwnuRIHtQLC.{0,1000}/ nocase ascii wide
        // Description: ThunderShell is a C# RAT that communicates via HTTP requests. All the network traffic is encrypted using a second layer of RC4 to avoid SSL interception and defeat network detection on the target system. RC4 is a weak cipher and is used to help obfuscate the traffic. HTTPS options should be used to provide integrity and strong encryption.
        // Reference: https://github.com/Mr-Un1k0d3r/ThunderShell
        $string5 = /.{0,1000}scripts.{0,1000}Remote\-WmiExecute\..{0,1000}/ nocase ascii wide
        // Description: ThunderShell is a C# RAT that communicates via HTTP requests. All the network traffic is encrypted using a second layer of RC4 to avoid SSL interception and defeat network detection on the target system. RC4 is a weak cipher and is used to help obfuscate the traffic. HTTPS options should be used to provide integrity and strong encryption.
        // Reference: https://github.com/Mr-Un1k0d3r/ThunderShell
        $string6 = /.{0,1000}scripts.{0,1000}Search\-EventForUser\.ps1.{0,1000}/ nocase ascii wide
        // Description: ThunderShell is a C# RAT that communicates via HTTP requests. All the network traffic is encrypted using a second layer of RC4 to avoid SSL interception and defeat network detection on the target system. RC4 is a weak cipher and is used to help obfuscate the traffic. HTTPS options should be used to provide integrity and strong encryption.
        // Reference: https://github.com/Mr-Un1k0d3r/ThunderShell
        $string7 = /.{0,1000}ThunderShell.{0,1000}/ nocase ascii wide
        // Description: ThunderShell is a C# RAT that communicates via HTTP requests. All the network traffic is encrypted using a second layer of RC4 to avoid SSL interception and defeat network detection on the target system. RC4 is a weak cipher and is used to help obfuscate the traffic. HTTPS options should be used to provide integrity and strong encryption.
        // Reference: https://github.com/Mr-Un1k0d3r/ThunderShell
        $string8 = /.{0,1000}ThunderShell\.git.{0,1000}/ nocase ascii wide
        // Description: ThunderShell is a C# RAT that communicates via HTTP requests. All the network traffic is encrypted using a second layer of RC4 to avoid SSL interception and defeat network detection on the target system. RC4 is a weak cipher and is used to help obfuscate the traffic. HTTPS options should be used to provide integrity and strong encryption.
        // Reference: https://github.com/Mr-Un1k0d3r/ThunderShell
        $string9 = /.{0,1000}ThunderShell\.py.{0,1000}/ nocase ascii wide
        // Description: ThunderShell is a C# RAT that communicates via HTTP requests. All the network traffic is encrypted using a second layer of RC4 to avoid SSL interception and defeat network detection on the target system. RC4 is a weak cipher and is used to help obfuscate the traffic. HTTPS options should be used to provide integrity and strong encryption.
        // Reference: https://github.com/Mr-Un1k0d3r/ThunderShell
        $string10 = /.{0,1000}ThunderShell\-master\.zip.{0,1000}/ nocase ascii wide
        // Description: ThunderShell is a C# RAT that communicates via HTTP requests. All the network traffic is encrypted using a second layer of RC4 to avoid SSL interception and defeat network detection on the target system. RC4 is a weak cipher and is used to help obfuscate the traffic. HTTPS options should be used to provide integrity and strong encryption.
        // Reference: https://github.com/Mr-Un1k0d3r/ThunderShell
        $string11 = /.{0,1000}YaWNdpwplLwycqWQDCyruhAFsYjWjnBA.{0,1000}/ nocase ascii wide

    condition:
        any of them
}

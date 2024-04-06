rule PickleC2
{
    meta:
        description = "Detection patterns for the tool 'PickleC2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PickleC2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PickleC2 is a post-exploitation and Lateral Movements framework
        // Reference: https://github.com/xRET2pwn/PickleC2
        $string1 = /\/PickleC2\.git/ nocase ascii wide
        // Description: PickleC2 is a post-exploitation and Lateral Movements framework
        // Reference: https://github.com/xRET2pwn/PickleC2
        $string2 = /\\Implants\\powershell\.ps1/ nocase ascii wide
        // Description: PickleC2 is a post-exploitation and Lateral Movements framework
        // Reference: https://github.com/xRET2pwn/PickleC2
        $string3 = /\\PickleC2\\Core\\.{0,1000}\.py/ nocase ascii wide
        // Description: PickleC2 is a post-exploitation and Lateral Movements framework
        // Reference: https://github.com/xRET2pwn/PickleC2
        $string4 = /\\PowerUp\.ps1/ nocase ascii wide
        // Description: PickleC2 is a post-exploitation and Lateral Movements framework
        // Reference: https://github.com/xRET2pwn/PickleC2
        $string5 = /data\/implant\/.{0,1000}\/host\.ps1/ nocase ascii wide
        // Description: PickleC2 is a post-exploitation and Lateral Movements framework
        // Reference: https://github.com/xRET2pwn/PickleC2
        $string6 = /Find\-PathDLLHijack/ nocase ascii wide
        // Description: PickleC2 is a post-exploitation and Lateral Movements framework
        // Reference: https://github.com/xRET2pwn/PickleC2
        $string7 = /Find\-ProcessDLLHijack/ nocase ascii wide
        // Description: PickleC2 is a post-exploitation and Lateral Movements framework
        // Reference: https://github.com/xRET2pwn/PickleC2
        $string8 = /http\:\/\/.{0,1000}\:.{0,1000}\/down\/.{0,1000}\/host\.ps1/ nocase ascii wide
        // Description: PickleC2 is a post-exploitation and Lateral Movements framework
        // Reference: https://github.com/xRET2pwn/PickleC2
        $string9 = /IgBJAHMAIABFAGwAZQB2AGEAdABlAGQAOgAgACQAKAAoAFsAUwBlAGMAdQByAGkAdAB5AC4AUAByAGkAbgBjAGkAcABhAGwALgBXAGkAbgBkAG8AdwBzAFAAcgBpAG4AYwBpAHAAYQBsAF0AWwBTAGUAYwB1AHIAaQB0AHkALgBQAHIAaQBuAGMAaQBwAGEAbAAuAFcAaQBuAGQAbwB3AHMASQBkAGUAbgB0AGkAdAB5AF0AOgA6AEcAZQB0AEMAdQByAHIAZQBuAHQAKAApACkALgBJAHMASQBuAFIAbwBsAGUAKABbAFMAZQBjAHUAcgBpAHQAeQAuAFAAcgBpAG4AYwBpAHAAYQBsAC4AVwBpAG4AZABvAHcAcwBCAHUAaQBsAHQASQBuAFIAbwBsAGUAXQAnAEEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIAJwApACkAIAAtACAAJAAoAEcAZQB0AC0ARABhAHQAZQApACIAIAB8ACAATwB1AHQALQBGAGkAbABlACAAQwA6AFwAVQBBAEMAQgB5AHAAYQBzAHMAVABlAHMAdAAuAHQAeAB0ACAALQBBAHAAcABlAG4AZAA\=/ nocase ascii wide
        // Description: PickleC2 is a post-exploitation and Lateral Movements framework
        // Reference: https://github.com/xRET2pwn/PickleC2
        $string10 = /Implants\/powershell\.ps1/ nocase ascii wide
        // Description: PickleC2 is a post-exploitation and Lateral Movements framework
        // Reference: https://github.com/xRET2pwn/PickleC2
        $string11 = /Invoke\-EventVwrBypass/ nocase ascii wide
        // Description: PickleC2 is a post-exploitation and Lateral Movements framework
        // Reference: https://github.com/xRET2pwn/PickleC2
        $string12 = /Invoke\-PrivescAudit\s/ nocase ascii wide
        // Description: PickleC2 is a post-exploitation and Lateral Movements framework
        // Reference: https://github.com/xRET2pwn/PickleC2
        $string13 = /Invoke\-ServiceAbuse/ nocase ascii wide
        // Description: PickleC2 is a post-exploitation and Lateral Movements framework
        // Reference: https://github.com/xRET2pwn/PickleC2
        $string14 = /module\spowerup/ nocase ascii wide
        // Description: PickleC2 is a post-exploitation and Lateral Movements framework
        // Reference: https://github.com/xRET2pwn/PickleC2
        $string15 = /PickleC2\-main/ nocase ascii wide
        // Description: PickleC2 is a post-exploitation and Lateral Movements framework
        // Reference: https://github.com/xRET2pwn/PickleC2
        $string16 = /UACBypassTest\.txt/ nocase ascii wide
        // Description: PickleC2 is a post-exploitation and Lateral Movements framework
        // Reference: https://github.com/xRET2pwn/PickleC2
        $string17 = /Write\-HijackDll/ nocase ascii wide
        // Description: PickleC2 is a post-exploitation and Lateral Movements framework
        // Reference: https://github.com/xRET2pwn/PickleC2
        $string18 = /xRET2pwn\/PickleC2/ nocase ascii wide

    condition:
        any of them
}

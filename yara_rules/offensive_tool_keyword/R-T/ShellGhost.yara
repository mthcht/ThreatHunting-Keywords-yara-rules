rule ShellGhost
{
    meta:
        description = "Detection patterns for the tool 'ShellGhost' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ShellGhost"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A memory-based evasion technique which makes shellcode invisible from process start to end
        // Reference: https://github.com/lem0nSec/ShellGhost
        $string1 = /\/ShellGhost\.git/ nocase ascii wide
        // Description: A memory-based evasion technique which makes shellcode invisible from process start to end
        // Reference: https://github.com/lem0nSec/ShellGhost
        $string2 = /lem0nSec\/ShellGhost/ nocase ascii wide
        // Description: A memory-based evasion technique which makes shellcode invisible from process start to end
        // Reference: https://github.com/lem0nSec/ShellGhost
        $string3 = /ShellGhost\.dll/ nocase ascii wide
        // Description: A memory-based evasion technique which makes shellcode invisible from process start to end
        // Reference: https://github.com/lem0nSec/ShellGhost
        $string4 = /ShellGhost\.exe/ nocase ascii wide
        // Description: A memory-based evasion technique which makes shellcode invisible from process start to end
        // Reference: https://github.com/lem0nSec/ShellGhost
        $string5 = /ShellGhost\.sln/ nocase ascii wide
        // Description: A memory-based evasion technique which makes shellcode invisible from process start to end
        // Reference: https://github.com/lem0nSec/ShellGhost
        $string6 = /ShellGhost\.vcxproj/ nocase ascii wide
        // Description: A memory-based evasion technique which makes shellcode invisible from process start to end
        // Reference: https://github.com/lem0nSec/ShellGhost
        $string7 = /ShellGhost_mapping\.py/ nocase ascii wide
        // Description: A memory-based evasion technique which makes shellcode invisible from process start to end
        // Reference: https://github.com/lem0nSec/ShellGhost
        $string8 = /ShellGhost\-master\.zip/ nocase ascii wide
        // Description: A memory-based evasion technique which makes shellcode invisible from process start to end
        // Reference: https://github.com/lem0nSec/ShellGhost
        $string9 = /src\/ShellGhost\.c/ nocase ascii wide

    condition:
        any of them
}

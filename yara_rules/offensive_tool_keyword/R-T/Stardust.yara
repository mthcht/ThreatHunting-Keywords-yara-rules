rule Stardust
{
    meta:
        description = "Detection patterns for the tool 'Stardust' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Stardust"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: An modern 64-bit position independent implant template
        // Reference: https://github.com/Cracked5pider/Stardust
        $string1 = /\"Stardust\sMessageBox\"/ nocase ascii wide
        // Description: An modern 64-bit position independent implant template
        // Reference: https://github.com/Cracked5pider/Stardust
        $string2 = /\/stardust\.x64\.exe/ nocase ascii wide
        // Description: An modern 64-bit position independent implant template
        // Reference: https://github.com/Cracked5pider/Stardust
        $string3 = /\/Stardust\/scripts\/loader\.x64\.exe/ nocase ascii wide
        // Description: An modern 64-bit position independent implant template
        // Reference: https://github.com/Cracked5pider/Stardust
        $string4 = /\/x64\/Stardust\.asm/ nocase ascii wide
        // Description: An modern 64-bit position independent implant template
        // Reference: https://github.com/Cracked5pider/Stardust
        $string5 = /\[\+\]\sExecute\sshellcode\.\.\.\spress\senter/ nocase ascii wide
        // Description: An modern 64-bit position independent implant template
        // Reference: https://github.com/Cracked5pider/Stardust
        $string6 = /\\stardust\.x64\.bin/ nocase ascii wide
        // Description: An modern 64-bit position independent implant template
        // Reference: https://github.com/Cracked5pider/Stardust
        $string7 = /\\stardust\.x64\.exe/ nocase ascii wide
        // Description: An modern 64-bit position independent implant template
        // Reference: https://github.com/Cracked5pider/Stardust
        $string8 = /\\Stardust\\scripts\\loader\.x64\.exe/ nocase ascii wide
        // Description: An modern 64-bit position independent implant template
        // Reference: https://github.com/Cracked5pider/Stardust
        $string9 = /\\x64\\Stardust\.asm/ nocase ascii wide
        // Description: An modern 64-bit position independent implant template
        // Reference: https://github.com/Cracked5pider/Stardust
        $string10 = /bin\/stardust\.x64\.bin/ nocase ascii wide
        // Description: An modern 64-bit position independent implant template
        // Reference: https://github.com/Cracked5pider/Stardust
        $string11 = /https\:\/\/5pider\.net\/blog\/2024\/01\/27\/modern\-shellcode\-implant\-design/ nocase ascii wide
        // Description: An modern 64-bit position independent implant template
        // Reference: https://github.com/Cracked5pider/Stardust
        $string12 = /loader\.x64\.exe\.exe/ nocase ascii wide
        // Description: An modern 64-bit position independent implant template
        // Reference: https://github.com/Cracked5pider/Stardust
        $string13 = /Stardust\.Win32\.NtProtectVirtualMemory\(/ nocase ascii wide
        // Description: An modern 64-bit position independent implant template
        // Reference: https://github.com/Cracked5pider/Stardust
        $string14 = /Stardust\.Win32\.RtlAllocateHeap\(/ nocase ascii wide
        // Description: An modern 64-bit position independent implant template
        // Reference: https://github.com/Cracked5pider/Stardust
        $string15 = /STARDUST_MACROS_H/ nocase ascii wide

    condition:
        any of them
}

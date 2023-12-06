rule micr0_shell
{
    meta:
        description = "Detection patterns for the tool 'micr0_shell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "micr0_shell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: micr0shell is a Python script that dynamically generates Windows X64 PIC Null-Free reverse shell shellcode.
        // Reference: https://github.com/senzee1984/micr0_shell
        $string1 = /\s\-\-execution\sfalse\s\-\-save\sTrue\s\-\-output\s.{0,1000}\.bin/ nocase ascii wide
        // Description: micr0shell is a Python script that dynamically generates Windows X64 PIC Null-Free reverse shell shellcode.
        // Reference: https://github.com/senzee1984/micr0_shell
        $string2 = /\s\-\-ip\s.{0,1000}\s\-\-port\s.{0,1000}\s\-\-type\scmd\s\-\-language\s/ nocase ascii wide
        // Description: micr0shell is a Python script that dynamically generates Windows X64 PIC Null-Free reverse shell shellcode.
        // Reference: https://github.com/senzee1984/micr0_shell
        $string3 = /\s\-\-ip\s.{0,1000}\s\-\-variable\sshellcode\s/ nocase ascii wide
        // Description: micr0shell is a Python script that dynamically generates Windows X64 PIC Null-Free reverse shell shellcode.
        // Reference: https://github.com/senzee1984/micr0_shell
        $string4 = /\/micr0\%20shell\.py/ nocase ascii wide
        // Description: micr0shell is a Python script that dynamically generates Windows X64 PIC Null-Free reverse shell shellcode.
        // Reference: https://github.com/senzee1984/micr0_shell
        $string5 = /\/micr0_shell\.git/ nocase ascii wide
        // Description: micr0shell is a Python script that dynamically generates Windows X64 PIC Null-Free reverse shell shellcode.
        // Reference: https://github.com/senzee1984/micr0_shell
        $string6 = /micr0\sshell\.py/ nocase ascii wide
        // Description: micr0shell is a Python script that dynamically generates Windows X64 PIC Null-Free reverse shell shellcode.
        // Reference: https://github.com/senzee1984/micr0_shell
        $string7 = /micr0_shell\-main/ nocase ascii wide
        // Description: micr0shell is a Python script that dynamically generates Windows X64 PIC Null-Free reverse shell shellcode.
        // Reference: https://github.com/senzee1984/micr0_shell
        $string8 = /micr0shell\.py\s/ nocase ascii wide
        // Description: micr0shell is a Python script that dynamically generates Windows X64 PIC Null-Free reverse shell shellcode.
        // Reference: https://github.com/senzee1984/micr0_shell
        $string9 = /senzee1984\/micr0_shell/ nocase ascii wide

    condition:
        any of them
}

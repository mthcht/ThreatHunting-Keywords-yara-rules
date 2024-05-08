rule Invisi_Shell
{
    meta:
        description = "Detection patterns for the tool 'Invisi-Shell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invisi-Shell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Hide your powershell script in plain sight! Invisi-Shell bypasses all of Powershell security features (ScriptBlock logging. Module logging. Transcription. AMSI) by hooking .Net assemblies. The hook is performed via CLR Profiler API.
        // Reference: https://github.com/OmerYa/Invisi-Shell
        $string1 = /\/Invisi\-Shell\.git/ nocase ascii wide
        // Description: Hide your powershell script in plain sight! Invisi-Shell bypasses all of Powershell security features (ScriptBlock logging. Module logging. Transcription. AMSI) by hooking .Net assemblies. The hook is performed via CLR Profiler API.
        // Reference: https://github.com/OmerYa/Invisi-Shell
        $string2 = /\\RunWithPathAsAdmin\.bat/ nocase ascii wide
        // Description: Hide your powershell script in plain sight! Invisi-Shell bypasses all of Powershell security features (ScriptBlock logging. Module logging. Transcription. AMSI) by hooking .Net assemblies. The hook is performed via CLR Profiler API.
        // Reference: https://github.com/OmerYa/Invisi-Shell
        $string3 = /\\RunWithRegistryNonAdmin\.bat/ nocase ascii wide
        // Description: Hide your powershell script in plain sight! Invisi-Shell bypasses all of Powershell security features (ScriptBlock logging. Module logging. Transcription. AMSI) by hooking .Net assemblies. The hook is performed via CLR Profiler API.
        // Reference: https://github.com/OmerYa/Invisi-Shell
        $string4 = /18A66118\-B98D\-4FFC\-AABE\-DAFF5779F14C/ nocase ascii wide
        // Description: Hide your powershell script in plain sight! Invisi-Shell bypasses all of Powershell security features (ScriptBlock logging. Module logging. Transcription. AMSI) by hooking .Net assemblies. The hook is performed via CLR Profiler API.
        // Reference: https://github.com/OmerYa/Invisi-Shell
        $string5 = /4a8e184ca9e1ccc775b224a48d344ce13dde26a86a634df2853ce7a27c17765c/ nocase ascii wide
        // Description: Hide your powershell script in plain sight! Invisi-Shell bypasses all of Powershell security features (ScriptBlock logging. Module logging. Transcription. AMSI) by hooking .Net assemblies. The hook is performed via CLR Profiler API.
        // Reference: https://github.com/OmerYa/Invisi-Shell
        $string6 = /833d68452ea956b5d23bcb243cd327bd05dfd79fb5a4a34064783749eafa1ddf/ nocase ascii wide
        // Description: Hide your powershell script in plain sight! Invisi-Shell bypasses all of Powershell security features (ScriptBlock logging. Module logging. Transcription. AMSI) by hooking .Net assemblies. The hook is performed via CLR Profiler API.
        // Reference: https://github.com/OmerYa/Invisi-Shell
        $string7 = /835747f27a37aa3fab9a116d7480701b813c16eba6b903eb82b96fa230aa992e/ nocase ascii wide
        // Description: Hide your powershell script in plain sight! Invisi-Shell bypasses all of Powershell security features (ScriptBlock logging. Module logging. Transcription. AMSI) by hooking .Net assemblies. The hook is performed via CLR Profiler API.
        // Reference: https://github.com/OmerYa/Invisi-Shell
        $string8 = /835747f27a37aa3fab9a116d7480701b813c16eba6b903eb82b96fa230aa992e/ nocase ascii wide
        // Description: Hide your powershell script in plain sight! Invisi-Shell bypasses all of Powershell security features (ScriptBlock logging. Module logging. Transcription. AMSI) by hooking .Net assemblies. The hook is performed via CLR Profiler API.
        // Reference: https://github.com/OmerYa/Invisi-Shell
        $string9 = /Invisi\-Shell/ nocase ascii wide
        // Description: Hide your powershell script in plain sight! Invisi-Shell bypasses all of Powershell security features (ScriptBlock logging. Module logging. Transcription. AMSI) by hooking .Net assemblies. The hook is performed via CLR Profiler API.
        // Reference: https://github.com/OmerYa/Invisi-Shell
        $string10 = /InvisiShellProfiler\.cpp/ nocase ascii wide
        // Description: Hide your powershell script in plain sight! Invisi-Shell bypasses all of Powershell security features (ScriptBlock logging. Module logging. Transcription. AMSI) by hooking .Net assemblies. The hook is performed via CLR Profiler API.
        // Reference: https://github.com/OmerYa/Invisi-Shell
        $string11 = /InvisiShellProfiler\.def/ nocase ascii wide
        // Description: Hide your powershell script in plain sight! Invisi-Shell bypasses all of Powershell security features (ScriptBlock logging. Module logging. Transcription. AMSI) by hooking .Net assemblies. The hook is performed via CLR Profiler API.
        // Reference: https://github.com/OmerYa/Invisi-Shell
        $string12 = /InvisiShellProfiler\.dll/ nocase ascii wide
        // Description: Hide your powershell script in plain sight! Invisi-Shell bypasses all of Powershell security features (ScriptBlock logging. Module logging. Transcription. AMSI) by hooking .Net assemblies. The hook is performed via CLR Profiler API.
        // Reference: https://github.com/OmerYa/Invisi-Shell
        $string13 = /InvisiShellProfiler\.h/ nocase ascii wide
        // Description: Hide your powershell script in plain sight! Invisi-Shell bypasses all of Powershell security features (ScriptBlock logging. Module logging. Transcription. AMSI) by hooking .Net assemblies. The hook is performed via CLR Profiler API.
        // Reference: https://github.com/OmerYa/Invisi-Shell
        $string14 = /InvisiShellProfiler\.pdb/ nocase ascii wide
        // Description: Hide your powershell script in plain sight! Invisi-Shell bypasses all of Powershell security features (ScriptBlock logging. Module logging. Transcription. AMSI) by hooking .Net assemblies. The hook is performed via CLR Profiler API.
        // Reference: https://github.com/OmerYa/Invisi-Shell
        $string15 = /InvisiShellProfiler\.vcxproj/ nocase ascii wide
        // Description: Hide your powershell script in plain sight! Invisi-Shell bypasses all of Powershell security features (ScriptBlock logging. Module logging. Transcription. AMSI) by hooking .Net assemblies. The hook is performed via CLR Profiler API.
        // Reference: https://github.com/OmerYa/Invisi-Shell
        $string16 = /OmerYa\/Invisi\-Shell/ nocase ascii wide

    condition:
        any of them
}

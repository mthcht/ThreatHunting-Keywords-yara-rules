rule CSExec
{
    meta:
        description = "Detection patterns for the tool 'CSExec' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CSExec"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string1 = /\s\-\-blockDLLs\s\-\-ruy\-lopez/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string2 = /\sCSExec\.py/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string3 = /\s\-\-dll\s\-\-dllhijack\s/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string4 = /\s\-\-donut\s\-\-rehash\sn\s\-\-silent\s\-o\s\/tmp\// nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string5 = /\s\-m\svenv\scsexec\s/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string6 = /\s\-\-no\-ppid\-spoof/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string7 = /\s\-\-no\-sigthief/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string8 = /\s\-pi\s\\\\\\\\\\\\\\\\\.\\\\\\\\pipe\\\\\\\\/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string9 = /\s\-s\sputty\.exe_sig\s/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string10 = /\s\-sc\sGetSyscallStub\s/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string11 = /\s\-sc\sSysWhispers3/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string12 = /\s\-\-shellcode\s.{0,1000}\-\-dc\-ip\s/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string13 = /\s\-\-shellcode\s.{0,1000}\-\-silent/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string14 = /\s\-\-shellcode\s\-\-remoteinject/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string15 = /\s\-\-silent\s\-obf\sNixImports\s\-o\s\/tmp\// nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string16 = /\s\-\-syscalls\sGetSyscallStub/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string17 = /\s\-\-syscalls\sSysWhispers3/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string18 = /\s\-\-syswhispers\s\-\-jump/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string19 = /\/CSExec\.py/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string20 = /\/CSExec\.py\.git/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string21 = /\~\/\.csexec/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string22 = /Attempted\sto\sspawn\sa\ssocks\sproxy\sserver\sat\s0\.0\.0\.0\:/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string23 = /beacon_generate\.py/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string24 = /bof_pack\.py\s/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string25 = /csexec\/csexec_history/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string26 = /dinjector\s\/i\:.{0,1000}\s\/p\:/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string27 = /dll_generator\.py/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string28 = /keethief\-syscalls/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string29 = /Metro\-Holografix\/CSExec/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string30 = /nanodump_pipe/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string31 = /nanodump\-pipes/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string32 = /NimSyscallLoader\s\-/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string33 = /\-\-noWAIT\s\-\-noFUNC\s\-\-donut\s\-\-rehash\sn\s\-\-silent\s\-o\s\/tmp\// nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string34 = /pypykatz\slsa\sminidump\s/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string35 = /reflective_assembly_minified\.ps1/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string36 = /reverse_shell_minified\.js/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string37 = /rlwrap\s\-cAr\snc\s\-lvnp\s/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string38 = /secretsdump\s.{0,1000}\-\-silent/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string39 = /sharpsecretsdump/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string40 = /SharpShot\.exe\s\// nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string41 = /temp.{0,1000}lsass_.{0,1000}\.dmp/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string42 = /templates.{0,1000}CSExec\.cs/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string43 = /templates.{0,1000}HIPS_LIPS_processes\.txt/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string44 = /templates.{0,1000}reflective_assembly_minified\.ps1/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string45 = /tmp.{0,1000}lsass_.{0,1000}\.dmp/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string46 = /utils\/payloads\.db/ nocase ascii wide

    condition:
        any of them
}

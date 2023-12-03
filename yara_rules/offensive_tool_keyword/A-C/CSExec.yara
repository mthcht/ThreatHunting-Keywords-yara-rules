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
        $string1 = /.{0,1000}\s\-\-blockDLLs\s\-\-ruy\-lopez.{0,1000}/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string2 = /.{0,1000}\sCSExec\.py.{0,1000}/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string3 = /.{0,1000}\s\-\-dll\s\-\-dllhijack\s.{0,1000}/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string4 = /.{0,1000}\s\-\-donut\s\-\-rehash\sn\s\-\-silent\s\-o\s\/tmp\/.{0,1000}/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string5 = /.{0,1000}\s\-m\svenv\scsexec\s.{0,1000}/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string6 = /.{0,1000}\s\-\-no\-ppid\-spoof.{0,1000}/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string7 = /.{0,1000}\s\-\-no\-sigthief.{0,1000}/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string8 = /.{0,1000}\s\-pi\s\\\\\\\\\\\\\\\\\.\\\\\\\\pipe\\\\\\\\.{0,1000}/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string9 = /.{0,1000}\s\-s\sputty\.exe_sig\s.{0,1000}/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string10 = /.{0,1000}\s\-sc\sGetSyscallStub\s.{0,1000}/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string11 = /.{0,1000}\s\-sc\sSysWhispers3.{0,1000}/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string12 = /.{0,1000}\s\-\-shellcode\s.{0,1000}\-\-dc\-ip\s.{0,1000}/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string13 = /.{0,1000}\s\-\-shellcode\s.{0,1000}\-\-silent.{0,1000}/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string14 = /.{0,1000}\s\-\-shellcode\s\-\-remoteinject.{0,1000}/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string15 = /.{0,1000}\s\-\-silent\s\-obf\sNixImports\s\-o\s\/tmp\/.{0,1000}/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string16 = /.{0,1000}\s\-\-syscalls\sGetSyscallStub.{0,1000}/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string17 = /.{0,1000}\s\-\-syscalls\sSysWhispers3.{0,1000}/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string18 = /.{0,1000}\s\-\-syswhispers\s\-\-jump.{0,1000}/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string19 = /.{0,1000}\/CSExec\.py.{0,1000}/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string20 = /.{0,1000}\/CSExec\.py\.git.{0,1000}/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string21 = /.{0,1000}~\/\.csexec.{0,1000}/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string22 = /.{0,1000}Attempted\sto\sspawn\sa\ssocks\sproxy\sserver\sat\s0\.0\.0\.0:.{0,1000}/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string23 = /.{0,1000}beacon_generate\.py.{0,1000}/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string24 = /.{0,1000}bof_pack\.py\s.{0,1000}/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string25 = /.{0,1000}csexec\/csexec_history.{0,1000}/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string26 = /.{0,1000}dinjector\s\/i:.{0,1000}\s\/p:.{0,1000}/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string27 = /.{0,1000}dll_generator\.py.{0,1000}/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string28 = /.{0,1000}keethief\-syscalls.{0,1000}/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string29 = /.{0,1000}Metro\-Holografix\/CSExec.{0,1000}/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string30 = /.{0,1000}nanodump_pipe.{0,1000}/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string31 = /.{0,1000}nanodump\-pipes.{0,1000}/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string32 = /.{0,1000}NimSyscallLoader\s\-.{0,1000}/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string33 = /.{0,1000}\-\-noWAIT\s\-\-noFUNC\s\-\-donut\s\-\-rehash\sn\s\-\-silent\s\-o\s\/tmp\/.{0,1000}/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string34 = /.{0,1000}pypykatz\slsa\sminidump\s.{0,1000}/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string35 = /.{0,1000}reflective_assembly_minified\.ps1.{0,1000}/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string36 = /.{0,1000}reverse_shell_minified\.js.{0,1000}/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string37 = /.{0,1000}rlwrap\s\-cAr\snc\s\-lvnp\s.{0,1000}/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string38 = /.{0,1000}secretsdump\s.{0,1000}\-\-silent.{0,1000}/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string39 = /.{0,1000}sharpsecretsdump.{0,1000}/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string40 = /.{0,1000}SharpShot\.exe\s\/.{0,1000}/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string41 = /.{0,1000}temp.{0,1000}lsass_.{0,1000}\.dmp.{0,1000}/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string42 = /.{0,1000}templates.{0,1000}CSExec\.cs.{0,1000}/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string43 = /.{0,1000}templates.{0,1000}HIPS_LIPS_processes\.txt.{0,1000}/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string44 = /.{0,1000}templates.{0,1000}reflective_assembly_minified\.ps1.{0,1000}/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string45 = /.{0,1000}tmp.{0,1000}lsass_.{0,1000}\.dmp.{0,1000}/ nocase ascii wide
        // Description: An alternative to *exec.py from impacket with some builtin tricks
        // Reference: https://github.com/Metro-Holografix/CSExec.py
        $string46 = /.{0,1000}utils\/payloads\.db.{0,1000}/ nocase ascii wide

    condition:
        any of them
}

rule RunasCs
{
    meta:
        description = "Detection patterns for the tool 'RunasCs' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RunasCs"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credential
        // Reference: https://github.com/antonioCoco/RunasCs
        $string1 = " --remote-impersonation" nocase ascii wide
        // Description: RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credential
        // Reference: https://github.com/antonioCoco/RunasCs
        $string2 = /\sRunasCs\.cs/ nocase ascii wide
        // Description: RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credential
        // Reference: https://github.com/antonioCoco/RunasCs
        $string3 = /\s\-Username\s.{0,1000}\s\-Password\s.{0,1000}\s\-Command\s.{0,1000}\s\-LogonType\s/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs
        $string4 = /\$RunasCsBase64/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs
        $string5 = /\/RunasCs\.cs/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string6 = /\/RunasCs\.exe/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs
        $string7 = /\/RunasCs\.git/ nocase ascii wide
        // Description: RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credential
        // Reference: https://github.com/antonioCoco/RunasCs
        $string8 = /\/RunasCs\.zip/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs
        $string9 = /\/RunasCs\.zip/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs
        $string10 = "/RunasCs/releases/download/" nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs
        $string11 = /\/RunasCs_binaries\.zip/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs
        $string12 = /\/RunasCs_x86\.zip/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs
        $string13 = /\\RunasCs\.cs/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string14 = /\\RunasCs\.exe/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs
        $string15 = /\\RunasCs\.zip/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs
        $string16 = /\\RunasCs_binaries\.zip/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs
        $string17 = /\\RunasCs_x86\.zip/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs
        $string18 = "041a1f05935a0aae4c4073a55cb9ddd0f356f3f9d5b9fd2355d6332961a226a5" nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs
        $string19 = "0d624761a03e400013f8372b931e658ceafef28f87574fc3af0421264ebbcb09" nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs
        $string20 = "168ca61eb4b45c7aa5b3b60df22a0d8122dee8d127a9b8a8e3ec5f427466edf9" nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs
        $string21 = "24722c45c461dfbcd1e5c9d2cba90bbc6fb32d2bff58b8fbbfb18a852f7eebde" nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs
        $string22 = "29df50927dfff1414f643367fcc9492dba40ebd2f518e1ec6cce25339ee73f6e" nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs
        $string23 = "433b8dd9a46d99f08c74b3ed9989848fe2e90498fbdac603b27812fb89be9340" nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs
        $string24 = "4b25648a17919f5d25080b160d998f02ace0c1fd3aab334dfe8ea53612cca954" nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs
        $string25 = "69058ca0c4eada431047c0376db8a4728feffbacebbb9578e59f4c9113a342ca" nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs
        $string26 = "69720fc90a8dca0c2ff3f33a59042ae0a6ddedd64d5fafefbc43583aa770e175" nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs
        $string27 = "780af7e91e49cdbbc34d44021232c4bb5df42b1584dd35b13a35c8cb670d2c0e" nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs
        $string28 = "847ff5d91e3c34f2e446ee6f6e2c76c9aafc25c76b031c9f8f45193840571176" nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs
        $string29 = "885a208a7a8ea9e37a44cef5ec2d8ee8ec7240e97b7ee7b9bda5dbf03553bf75" nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs
        $string30 = "88f826096be1ed1be32dd45dc2381189df7c5f349c7b808edb872e68be4a9350" nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs
        $string31 = "89269edf8f752740d81254dd68ae0c8ed29d18cfb8582620e4759b48ad47ddb3" nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs
        $string32 = "8a1699ce5630406091ec92ceec25f46a587888d228f3a9322dbaf9857cb3b5b7" nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs
        $string33 = "9e53f4d6daccf2c7f5f8acbe56160e6f7301f3bdd05e067cb2be6c7f17e0c482" nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs
        $string34 = "9f17e90125023767fcb54bc9573f20b89a50772134e502f92832b6b00df68768" nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs
        $string35 = "antonioCoco/RunasCs" nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs
        $string36 = /base64_conversion_commands\.ps1/ nocase ascii wide
        // Description: RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credential
        // Reference: https://github.com/antonioCoco/RunasCs
        $string37 = /\-\-bypass\-uac.{0,1000}\-\-logontype/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs
        $string38 = "c235329bd192781dad37dc190bbce353f3f7ade3a98b6d1c79e2ab69a91f26ff" nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs
        $string39 = /cmd\s\/c\s.{0,1000}\s\-\-bypass\-uac/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs
        $string40 = /cmd\s\/c\s.{0,1000}\s\-\-remote\-impersonation/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs
        $string41 = "d7568417704e64ca524b45240eadd4ddabfb1f477f9eecc37f6bc5654ee7d184" nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs
        $string42 = "db5edbf21647b80f858790642c32e9c41884339b505d62ceebcfabb74a44db15" nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs
        $string43 = "e470b90efe8da89e3c118eea1d62eea1f4f0194d82522c7dfb2a07d24471566a" nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs
        $string44 = "e70c4d485153cf47b9dde0d1124b48e929e9838e241956b0062fafcd51a2f4f6" nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs
        $string45 = "Invoke-RunasCs -" nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs
        $string46 = "Invoke-RunasCs" nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string47 = "Invoke-RunasCs" nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs
        $string48 = /Invoke\-RunasCs\.ps1/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string49 = "'Product'>RunasCs<" nocase ascii wide
        // Description: RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credential
        // Reference: https://github.com/antonioCoco/RunasCs
        $string50 = "RunasCreateProcessAsUserW" nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string51 = /RunasCs\sv1\.5\s\-\s\@splinter_code/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string52 = /RunasCs.{0,1000}\s\-\-remote\-impersonation/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs
        $string53 = /RunasCs\.exe/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs
        $string54 = /RunasCs\.zip/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs
        $string55 = /RunasCs_net2\.exe/ nocase ascii wide

    condition:
        any of them
}

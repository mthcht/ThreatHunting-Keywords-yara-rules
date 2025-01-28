rule ATPMiniDump
{
    meta:
        description = "Detection patterns for the tool 'ATPMiniDump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ATPMiniDump"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Dumping LSASS memory with MiniDumpWriteDump on PssCaptureSnapShot to evade WinDefender ATP credential-theft. Take a look at this blog post for details. ATPMiniDump was created starting from Outflank-Dumpert then big credits to @Cneelis
        // Reference: https://github.com/b4rtik/ATPMiniDump
        $string1 = /\/ATPMiniDump\.git/ nocase ascii wide
        // Description: Dumping LSASS memory with MiniDumpWriteDump on PssCaptureSnapShot to evade WinDefender ATP credential-theft. Take a look at this blog post for details. ATPMiniDump was created starting from Outflank-Dumpert then big credits to @Cneelis
        // Reference: https://github.com/b4rtik/ATPMiniDump
        $string2 = /\[\!\]\sFailed\sto\screate\sminidump/ nocase ascii wide
        // Description: Dumping LSASS memory with MiniDumpWriteDump on PssCaptureSnapShot to evade WinDefender ATP credential-theft. Take a look at this blog post for details. ATPMiniDump was created starting from Outflank-Dumpert then big credits to @Cneelis
        // Reference: https://github.com/b4rtik/ATPMiniDump
        $string3 = /\\dumpert\.dmp/ nocase ascii wide
        // Description: Dumping LSASS memory with MiniDumpWriteDump on PssCaptureSnapShot to evade WinDefender ATP credential-theft. Take a look at this blog post for details. ATPMiniDump was created starting from Outflank-Dumpert then big credits to @Cneelis
        // Reference: https://github.com/b4rtik/ATPMiniDump
        $string4 = "0538b3096657777e14c5ac6296037b936df7fb375d32199b0ae1b7fe33b3d63b" nocase ascii wide
        // Description: Dumping LSASS memory with MiniDumpWriteDump on PssCaptureSnapShot to evade WinDefender ATP credential-theft. Take a look at this blog post for details. ATPMiniDump was created starting from Outflank-Dumpert then big credits to @Cneelis
        // Reference: https://github.com/b4rtik/ATPMiniDump
        $string5 = "53a8f4b6cd47f980a97be192fdbf70c028065c7bfdf2e461927c7561eafbea6b" nocase ascii wide
        // Description: Dumping LSASS memory with MiniDumpWriteDump on PssCaptureSnapShot to evade WinDefender ATP credential-theft. Take a look at this blog post for details. ATPMiniDump was created starting from Outflank-Dumpert then big credits to @Cneelis
        // Reference: https://github.com/b4rtik/ATPMiniDump
        $string6 = "920B8C5B-0DC5-4BD7-B6BB-D14B39BFC9FE" nocase ascii wide
        // Description: Dumping LSASS memory with MiniDumpWriteDump on PssCaptureSnapShot to evade WinDefender ATP credential-theft. Take a look at this blog post for details. ATPMiniDump was created starting from Outflank-Dumpert then big credits to @Cneelis
        // Reference: https://github.com/b4rtik/ATPMiniDump
        $string7 = "ATPMiniDump" nocase ascii wide
        // Description: Dumping LSASS memory with MiniDumpWriteDump on PssCaptureSnapShot to evade WinDefender ATP credential-theft. Take a look at this blog post for details. ATPMiniDump was created starting from Outflank-Dumpert then big credits to @Cneelis
        // Reference: https://github.com/b4rtik/ATPMiniDump
        $string8 = "b4rtik/ATPMiniDump" nocase ascii wide
        // Description: Dumping LSASS memory with MiniDumpWriteDump on PssCaptureSnapShot to evade WinDefender ATP credential-theft. Take a look at this blog post for details. ATPMiniDump was created starting from Outflank-Dumpert then big credits to @Cneelis
        // Reference: https://github.com/b4rtik/ATPMiniDump
        $string9 = "By b4rtik & uf0" nocase ascii wide
        // Description: Dumping LSASS memory with MiniDumpWriteDump on PssCaptureSnapShot to evade WinDefender ATP credential-theft. Take a look at this blog post for details. ATPMiniDump was created starting from Outflank-Dumpert then big credits to @Cneelis
        // Reference: https://github.com/b4rtik/ATPMiniDump
        $string10 = "C7A0003B-98DC-4D57-8F09-5B90AAEFBDF4" nocase ascii wide
        // Description: Dumping LSASS memory with MiniDumpWriteDump on PssCaptureSnapShot to evade WinDefender ATP credential-theft. Take a look at this blog post for details. ATPMiniDump was created starting from Outflank-Dumpert then big credits to @Cneelis
        // Reference: https://github.com/b4rtik/ATPMiniDump
        $string11 = "Dumping LSASS memory with MiniDumpWriteDump on PssCaptureSnapShot" nocase ascii wide

    condition:
        any of them
}

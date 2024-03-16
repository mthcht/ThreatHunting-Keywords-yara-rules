rule PetitPotato
{
    meta:
        description = "Detection patterns for the tool 'PetitPotato' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PetitPotato"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Local privilege escalation via PetitPotam (Abusing impersonate privileges)
        // Reference: https://github.com/wh0amitz/PetitPotato
        $string1 = /\sPetitPotato\.cpp/ nocase ascii wide
        // Description: Local privilege escalation via PetitPotam (Abusing impersonate privileges)
        // Reference: https://github.com/wh0amitz/PetitPotato
        $string2 = /\.exe\s3\scmd/ nocase ascii wide
        // Description: Local privilege escalation via PetitPotam (Abusing impersonate privileges)
        // Reference: https://github.com/wh0amitz/PetitPotato
        $string3 = /\/PetitPotato\.cpp/ nocase ascii wide
        // Description: Local privilege escalation via PetitPotam (Abusing impersonate privileges)
        // Reference: https://github.com/wh0amitz/PetitPotato
        $string4 = /\/PetitPotato\.git/ nocase ascii wide
        // Description: Local privilege escalation via PetitPotam (Abusing impersonate privileges)
        // Reference: https://github.com/wh0amitz/PetitPotato
        $string5 = /\/PetitPotato\-1\.0\.0\.zip/ nocase ascii wide
        // Description: Local privilege escalation via PetitPotam (Abusing impersonate privileges)
        // Reference: https://github.com/wh0amitz/PetitPotato
        $string6 = /\[\+\]\sInvoking\sEfsRpcAddUsersToFile\swith\starget\spath\:\s/ nocase ascii wide
        // Description: Local privilege escalation via PetitPotam (Abusing impersonate privileges)
        // Reference: https://github.com/wh0amitz/PetitPotato
        $string7 = /\[\+\]\sInvoking\sEfsRpcAddUsersToFileEx\swith\starget\spath\:\s/ nocase ascii wide
        // Description: Local privilege escalation via PetitPotam (Abusing impersonate privileges)
        // Reference: https://github.com/wh0amitz/PetitPotato
        $string8 = /\[\+\]\sInvoking\sEfsRpcDecryptFileSrv\swith\starget\spath\:\s/ nocase ascii wide
        // Description: Local privilege escalation via PetitPotam (Abusing impersonate privileges)
        // Reference: https://github.com/wh0amitz/PetitPotato
        $string9 = /\[\+\]\sInvoking\sEfsRpcDuplicateEncryptionInfoFile\swith\starget\spath\:\s/ nocase ascii wide
        // Description: Local privilege escalation via PetitPotam (Abusing impersonate privileges)
        // Reference: https://github.com/wh0amitz/PetitPotato
        $string10 = /\[\+\]\sInvoking\sEfsRpcDuplicateEncryptionInfoFile\swith\starget\spath\:/ nocase ascii wide
        // Description: Local privilege escalation via PetitPotam (Abusing impersonate privileges)
        // Reference: https://github.com/wh0amitz/PetitPotato
        $string11 = /\[\+\]\sInvoking\sEfsRpcEncryptFileSrv\swith\starget\spath\:\s/ nocase ascii wide
        // Description: Local privilege escalation via PetitPotam (Abusing impersonate privileges)
        // Reference: https://github.com/wh0amitz/PetitPotato
        $string12 = /\[\+\]\sInvoking\sEfsRpcFileKeyInfo\swith\starget\spath\:\s/ nocase ascii wide
        // Description: Local privilege escalation via PetitPotam (Abusing impersonate privileges)
        // Reference: https://github.com/wh0amitz/PetitPotato
        $string13 = /\[\+\]\sInvoking\sEfsRpcFileKeyInfoEx\swith\starget\spath\:\s/ nocase ascii wide
        // Description: Local privilege escalation via PetitPotam (Abusing impersonate privileges)
        // Reference: https://github.com/wh0amitz/PetitPotato
        $string14 = /\[\+\]\sInvoking\sEfsRpcGetEncryptedFileMetadata\swith\starget\spath\:\s/ nocase ascii wide
        // Description: Local privilege escalation via PetitPotam (Abusing impersonate privileges)
        // Reference: https://github.com/wh0amitz/PetitPotato
        $string15 = /\[\+\]\sInvoking\sEfsRpcOpenFileRaw\swith\starget\spath\:\s/ nocase ascii wide
        // Description: Local privilege escalation via PetitPotam (Abusing impersonate privileges)
        // Reference: https://github.com/wh0amitz/PetitPotato
        $string16 = /\[\+\]\sInvoking\sEfsRpcQueryRecoveryAgents\swith\starget\spath\:\s/ nocase ascii wide
        // Description: Local privilege escalation via PetitPotam (Abusing impersonate privileges)
        // Reference: https://github.com/wh0amitz/PetitPotato
        $string17 = /\[\+\]\sInvoking\sEfsRpcQueryUsersOnFile\swith\starget\spath\:\s/ nocase ascii wide
        // Description: Local privilege escalation via PetitPotam (Abusing impersonate privileges)
        // Reference: https://github.com/wh0amitz/PetitPotato
        $string18 = /\[\+\]\sInvoking\sEfsRpcRemoveUsersFromFile\swith\starget\spath\:\s/ nocase ascii wide
        // Description: Local privilege escalation via PetitPotam (Abusing impersonate privileges)
        // Reference: https://github.com/wh0amitz/PetitPotato
        $string19 = /\[\+\]\sInvoking\sEfsRpcSetEncryptedFileMetadata\swith\starget\spath\:\s/ nocase ascii wide
        // Description: Local privilege escalation via PetitPotam (Abusing impersonate privileges)
        // Reference: https://github.com/wh0amitz/PetitPotato
        $string20 = /\[\+\]\sMalicious\snamed\spipe\srunning\son\s/ nocase ascii wide
        // Description: Local privilege escalation via PetitPotam (Abusing impersonate privileges)
        // Reference: https://github.com/wh0amitz/PetitPotato
        $string21 = /\\\\localhost\/pipe\/petit\\/ nocase ascii wide
        // Description: Local privilege escalation via PetitPotam (Abusing impersonate privileges)
        // Reference: https://github.com/wh0amitz/PetitPotato
        $string22 = /\\\\pipe\\\\petit\\\\pipe\\\\srvsvc/ nocase ascii wide
        // Description: Local privilege escalation via PetitPotam (Abusing impersonate privileges)
        // Reference: https://github.com/wh0amitz/PetitPotato
        $string23 = /\\C\$\\wh0nqs\.txt\./ nocase ascii wide
        // Description: Local privilege escalation via PetitPotam (Abusing impersonate privileges)
        // Reference: https://github.com/wh0amitz/PetitPotato
        $string24 = /\\petit\\pipe\\srvsvc/ nocase ascii wide
        // Description: Local privilege escalation via PetitPotam (Abusing impersonate privileges)
        // Reference: https://github.com/wh0amitz/PetitPotato
        $string25 = /\\PetitPotato\.cpp/ nocase ascii wide
        // Description: Local privilege escalation via PetitPotam (Abusing impersonate privileges)
        // Reference: https://github.com/wh0amitz/PetitPotato
        $string26 = /\\PetitPotato\.log/ nocase ascii wide
        // Description: Local privilege escalation via PetitPotam (Abusing impersonate privileges)
        // Reference: https://github.com/wh0amitz/PetitPotato
        $string27 = /\\petitpotato\.obj/ nocase ascii wide
        // Description: Local privilege escalation via PetitPotam (Abusing impersonate privileges)
        // Reference: https://github.com/wh0amitz/PetitPotato
        $string28 = /\\petitpotato\.pdb/ nocase ascii wide
        // Description: Local privilege escalation via PetitPotam (Abusing impersonate privileges)
        // Reference: https://github.com/wh0amitz/PetitPotato
        $string29 = /\\PetitPotato\.sln/ nocase ascii wide
        // Description: Local privilege escalation via PetitPotam (Abusing impersonate privileges)
        // Reference: https://github.com/wh0amitz/PetitPotato
        $string30 = /\\PetitPotato\.tlog/ nocase ascii wide
        // Description: Local privilege escalation via PetitPotam (Abusing impersonate privileges)
        // Reference: https://github.com/wh0amitz/PetitPotato
        $string31 = /\\PetitPotato\.vcxproj/ nocase ascii wide
        // Description: Local privilege escalation via PetitPotam (Abusing impersonate privileges)
        // Reference: https://github.com/wh0amitz/PetitPotato
        $string32 = /\\petitpotato\\x64\\/ nocase ascii wide
        // Description: Local privilege escalation via PetitPotam (Abusing impersonate privileges)
        // Reference: https://github.com/wh0amitz/PetitPotato
        $string33 = /\\PetitPotato\-1\.0\.0\.zip/ nocase ascii wide
        // Description: Local privilege escalation via PetitPotam (Abusing impersonate privileges)
        // Reference: https://github.com/wh0amitz/PetitPotato
        $string34 = /\\PetitPotato\-1\.0\.0\\/ nocase ascii wide
        // Description: Local privilege escalation via PetitPotam (Abusing impersonate privileges)
        // Reference: https://github.com/wh0amitz/PetitPotato
        $string35 = /A315E53B\-397A\-4074\-B988\-535A100D45DC/ nocase ascii wide
        // Description: Local privilege escalation via PetitPotam (Abusing impersonate privileges)
        // Reference: https://github.com/wh0amitz/PetitPotato
        $string36 = /e55c85d7da9a60ed31867b421961b3503df0b464e068e584fccc20892b05bef2/ nocase ascii wide
        // Description: Local privilege escalation via PetitPotam (Abusing impersonate privileges)
        // Reference: https://github.com/wh0amitz/PetitPotato
        $string37 = /eb760ea670e63083e0fef40c12861c6459ebf28b86129c8d3fa200714b2a0b02/ nocase ascii wide
        // Description: Local privilege escalation via PetitPotam (Abusing impersonate privileges)
        // Reference: https://github.com/wh0amitz/PetitPotato
        $string38 = /PetitPotam\sbypass\svia\sRPC_C_AUTHN_LEVEL_PKT_PRIVACY/ nocase ascii wide
        // Description: Local privilege escalation via PetitPotam (Abusing impersonate privileges)
        // Reference: https://github.com/wh0amitz/PetitPotato
        $string39 = /PetitPotato\s3\scmd/ nocase ascii wide
        // Description: Local privilege escalation via PetitPotam (Abusing impersonate privileges)
        // Reference: https://github.com/wh0amitz/PetitPotato
        $string40 = /PetitPotato\.Build\.CppClean\.log\,/ nocase ascii wide
        // Description: Local privilege escalation via PetitPotam (Abusing impersonate privileges)
        // Reference: https://github.com/wh0amitz/PetitPotato
        $string41 = /PetitPotato\.exe/ nocase ascii wide
        // Description: Local privilege escalation via PetitPotam (Abusing impersonate privileges)
        // Reference: https://github.com/wh0amitz/PetitPotato
        $string42 = /PetitPotato\.lastbuildstate/ nocase ascii wide
        // Description: Local privilege escalation via PetitPotam (Abusing impersonate privileges)
        // Reference: https://github.com/wh0amitz/PetitPotato
        $string43 = /wh0amitz\/PetitPotato/ nocase ascii wide

    condition:
        any of them
}

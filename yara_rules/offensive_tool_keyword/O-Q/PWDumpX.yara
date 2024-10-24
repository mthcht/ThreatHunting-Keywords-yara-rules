rule PWDumpX
{
    meta:
        description = "Detection patterns for the tool 'PWDumpX' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PWDumpX"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string1 = /\sDumpSvc\.exe/ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string2 = /\sPWDumpX\sprocess\s/ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string3 = /\sPWDumpX\sservice\s/ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string4 = /\/DumpSvc\.exe/ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string5 = /\\DumpExt\.dll/ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string6 = /\\DumpSvc\.exe/ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string7 = /\\LSASecrets\.txt/ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string8 = /\\PWDumpX\.c/ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string9 = /\\PWHashes\.txt/ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string10 = /\\services\\PWDumpX\\/ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string11 = /_DumpLSASecrets/ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string12 = /\>PWDumpX\sService\</ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string13 = /12e55226b801ebdfcc9334ca438a57db1da463de48e2893009a7bb3e5e5e0dbc/ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string14 = /3f5ea2764696b07fdb61c7b34736eae26518ed2e36a624df09fb37025659201f/ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string15 = /3f5ea2764696b07fdb61c7b34736eae26518ed2e36a624df09fb37025659201f/ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string16 = /52b9c0a0a0188e47cb4b812aabe5a1832633fe9d66cebf702dfe0de114db0abd/ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string17 = /5c85b965c19ff7f7742980f90965279aa0ae2ea4c50317ad7680b56d6e3ed9d5/ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string18 = /78b4ff5e1bbac4a8bde265705a5c6e36b41bb2a9170f8f060a09bb1552549af2/ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string19 = /79c1d4ab8f425095d2d9f2a18a0cab08d31b686b149fba3db24a13e2bc7299ee/ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string20 = /80a9520b464f4bd7b4747c897a66a3c41a9100cb9efcd94614e2bd053247285a/ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string21 = /Cannot\senable\sSE_DEBUG_NAME\sprivilege\son\sremote\shost/ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string22 = /Cannot\sget\sLSASS\sPID\son\sremote\shost/ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string23 = /Cannot\sload\sSAM\sfunctions\son\sremote\shost/ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string24 = /Cannot\sopen\sLSA\spolicy\son\sremote\shost/ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string25 = /Cannot\sopen\sregistry\skey\sHKLM\\SECURITY\\Policy\\Secrets\son\sremote\shost/ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string26 = /Cannot\sopen\sSAM\son\sremote\shost/ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string27 = /https\:\/\/reedarvin\.thearvins\.com\// nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string28 = /\-LIBGCCW32\-EH\-3\-SJLJ\-GTHR\-MINGW32/ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string29 = /\-LSASecrets\.txt/ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string30 = /PWDumpDLLPath/ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string31 = /PWDumpEXEPath/ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string32 = /PWDumpX\s/ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string33 = /PWDumpX\sv1\.0/ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string34 = /PWDumpX\.zip/ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string35 = /\-PWHashes\.txt/ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string36 = /reedarvin\@gmail\.com/ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string37 = /szRemotePWDumpEXEPath/ nocase ascii wide

    condition:
        any of them
}

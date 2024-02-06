rule D3m0n1z3dShell
{
    meta:
        description = "Detection patterns for the tool 'D3m0n1z3dShell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "D3m0n1z3dShell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string1 = /\.bashrc\spersistence\ssetup\ssuccessfully/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string2 = /\/chisel_x32/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string3 = /\/chisel_x64/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string4 = /\/D3m0n1z3dShell\.git/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string5 = /\/D3m0n1z3dShell\/archive\// nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string6 = /\/deepce\.sh/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string7 = /\/install_locutus\.sh/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string8 = /\/linpeas\.sh/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string9 = /\/tmp\/borg_d3monized/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string10 = /\/tmp\/tmpfolder\/pingoor\.c/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string11 = /\/tmp\/tmpfolder\/pingoor\.h/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string12 = /\[D3m0niz3d\]\~\#/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string13 = /\\chisel_x32/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string14 = /\\chisel_x64/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string15 = /addPreloadToPrivesc/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string16 = /bashRCPersistence/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string17 = /D3m0n1z3dShell\-main/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string18 = /deepce\.sh\s\-e\s/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string19 = /demonizedshell\.sh/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string20 = /demonizedshell_static\.sh/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string21 = /discovery_port_scan/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string22 = /dumpcreds.{0,1000}mimipenguin/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string23 = /I2lmbmRlZiBQSU5HT09SCiNkZWZpbmUgUElOR09PUgoKI2RlZmluZSBTRVJWRVJJUCAiM/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string24 = /icmpBackdoor/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string25 = /implant_rootkit\.sh/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string26 = /lkmRootkitmodified/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string27 = /MatheuZSecurity\/D3m0n1z3dShell/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string28 = /mimipenguin\.py/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string29 = /mimipenguin\.sh/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string30 = /MotdPersistence/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string31 = /pwd\|passwd\|password\|PASSWD\|PASSWORD\|dbuser\|dbpass\|pass/ nocase ascii wide
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string32 = /su_brute_user_num/ nocase ascii wide

    condition:
        any of them
}

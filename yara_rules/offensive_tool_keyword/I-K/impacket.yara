rule impacket
{
    meta:
        description = "Detection patterns for the tool 'impacket' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "impacket"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string1 = /\sdacledit\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string2 = /\s\-dc\-ip\s.{0,1000}\s\s\-so\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string3 = /\s\-dc\-ip\s.{0,1000}\s\-computer\-pass\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string4 = /\s\-dc\-ip\s.{0,1000}\s\-impersonate\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string5 = /\s\-dc\-ip\s.{0,1000}\s\-target\-ip\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket/blob/master/examples/getST.py
        $string6 = /\s\-force\-forwardable/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string7 = /\s\-hashes\s.{0,1000}\s\-spn\s.{0,1000}\s\-impersonate\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string8 = /\simpacket/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string9 = /\simpacket\// nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket/blob/master/examples/getST.py
        $string10 = /\s\-impersonate.{0,1000}\s\-hashes/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string11 = /\s\-just\-dc\-ntlm\s\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string12 = /\s\-just\-dc\-user\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string13 = /\s\-k\s\-request\-user\s.{0,1000}\s\-dc\-ip/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string14 = /\sLMHASH\:NTHASH/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string15 = /\s\-no\-pass\s\-usersfile\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string16 = /\s\-ntds\s.{0,1000}\.dit\s.{0,1000}\-system\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string17 = /\s\-ntds\sntds\.dit\s\-system\sSYSTEM\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string18 = /\s\-nthash\s.{0,1000}\s\-domain\-sid\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string19 = /\sntlm\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket/blob/master/examples/getST.py
        $string20 = /\sPrincipalsAllowedToDelegateToAccount\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference
        $string21 = /\s\-sam\s.{0,1000}\s\-system\s.{0,1000}\s\-security\s.{0,1000}\sLOCAL\s\>\s.{0,1000}\.out/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string22 = /\s\-\-shadow\-credentials\s\-\-shadow\-target\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket/blob/master/examples/getST.py
        $string23 = /\s\-spn\scifs\/.{0,1000}\s\-hashes/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string24 = /\s\-system\sSYSTEM\s\-ntds\sNTDS\.dit\sLOCAL/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string25 = /\s\-system\sSYSTEM\s\-ntds\sNTDS\.dit\s\-outputfile/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string26 = /\s\-target\-domain\s.{0,1000}\s\-outputfile\s.{0,1000}\s\-no\-pass/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string27 = /\.py\s.{0,1000}\s\-k\s\-no\-pass/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string28 = /\/atexec\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string29 = /\/attacks\/.{0,1000}\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string30 = /\/dacledit\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string31 = /\/exchanger\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string32 = /\/getST\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string33 = /\/impacket\./ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string34 = /\/impacket\// nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string35 = /\/kerberos\-ldap\-password\-hunter/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string36 = /\/krb5\/.{0,1000}\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string37 = /\/ldap\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string38 = /\/lookupsid\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string39 = /\/ntlm\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string40 = /\/ping6\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string41 = /\/smb\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string42 = /\/SMB_RPC\/.{0,1000}\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string43 = /\/smb3\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string44 = /\/sniff\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string45 = /\/winregistry\.py.{0,1000}/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string46 = /\:9090.{0,1000}\/api\/v1\.0\/relays/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string47 = /\?convert_ccache_to_kirbi/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string48 = /\?convert_kirbi_to_ccache/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string49 = /\\\$.{0,1000}\.kirbi/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string50 = /\\\\127\.0\.0\.1\\c\$/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string51 = /\\dacledit\-.{0,1000}\.bak/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string52 = /\\dacledit\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string53 = /\\impacket\./ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string54 = /\\krb5\\.{0,1000}\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string55 = /\\ntlm\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string56 = /\\SMB_RPC\\.{0,1000}\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string57 = /\\sniff\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string58 = /41414141\-4141\-4141\-4141\-414141414141/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string59 = /adcsattack\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string60 = /addcomputer\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string61 = /admin\.kirbi/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string62 = /atexec\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string63 = /cat\s.{0,1000}\.ntds/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string64 = /changepasswd\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string65 = /cmd\.exe\s\/Q\s\/c\scd\s\\\s1\>\s\\\\127\.0\.0\.1\\ADMIN\$\\__.{0,1000}\s2\>\&1/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string66 = /db8b7152534b483ed966cd9557bed083106b448feea5e06d6963c0bd7b282f40/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string67 = /dcomexec\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string68 = /dcsyncattack\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string69 = /dcsyncclient\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string70 = /dpapi\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string71 = /DumpNTLMInfo\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string72 = /examples\/netview\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string73 = /findDelegation\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket/blob/master/examples/getST.py
        $string74 = /\-force\-forwardableet\-ADComputer/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string75 = /fortra\/impacket/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string76 = /FrameManagementAssociationRequest\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string77 = /FrameManagementDeauthentication\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string78 = /FrameManagementProbeRequest\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string79 = /FrameManagementReassociationResponse\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string80 = /GetADUsers\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string81 = /Get\-GPPPassword\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string82 = /GetNPUsers\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string83 = /getPac\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string84 = /getTGT\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string85 = /GetUserSPNs\./ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string86 = /goldenPac\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string87 = /http\:\/\/127\.0\.0\.1\:9090\// nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string88 = /http\:\/\/localhost\:9090\// nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string89 = /httpattack\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string90 = /httpattacks\/.{0,1000}\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string91 = /httprelayclient\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string92 = /httprelayserver\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string93 = /imapattack\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string94 = /imaprelayclient\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself. Packets can be constructed from scratch. as well as parsed from raw data. and the object oriented API makes it simple to work with deep hierarchies of protocols. The library provides a set of tools as examples of what can be done within the context of this library
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string95 = /impacket/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself. Packets can be constructed from scratch. as well as parsed from raw data. and the object oriented API makes it simple to work with deep hierarchies of protocols. The library provides a set of tools as examples of what can be done within the context of this library.
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string96 = /impacket/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string97 = /impacket\-.{0,1000}\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string98 = /impacket\-.{0,1000}\.tar\.gz/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string99 = /\'impacket\./ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string100 = /impacket\.git/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string101 = /impacket\.krb5\.asn1/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string102 = /impacket\.krb5\.ccache/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string103 = /impacket\.krb5\.kerberosv5/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string104 = /impacket\.ldap/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string105 = /impacket\.msada_guids/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string106 = /impacket\.ntlm/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string107 = /impacket\/.{0,1000}\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string108 = /impacket\:latest/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string109 = /impacket__init__/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string110 = /impacket\-atexec/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string111 = /impacket\-dcomexec/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string112 = /impacket\-GetADUsers/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string113 = /impacket\-GetNPUsers/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string114 = /impacket\-getST/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string115 = /impacket\-getTGT/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string116 = /impacketldap_shell/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string117 = /impacketlogger/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string118 = /impacket\-lookupsid/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string119 = /impacketmssqlshell/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string120 = /impacket\-netview/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string121 = /impacketntlmrelayx/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string122 = /impacketos_ident/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string123 = /impacket\-psexec/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string124 = /impacket\-reg/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself. Packets can be constructed from scratch. as well as parsed from raw data. and the object oriented API makes it simple to work with deep hierarchies of protocols. The library provides a set of tools as examples of what can be done within the context of this library
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string125 = /impacket\-reg/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string126 = /impacketremcomsvc/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string127 = /impacketrpcdatabase/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string128 = /impacket\-rpcdump/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string129 = /impacket\-samrdump/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string130 = /impacketsecretsdump/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference
        $string131 = /impacket\-secretsdump/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string132 = /impacket\-secretsdump/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string133 = /impacketserviceinstall/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string134 = /impacket\-services/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string135 = /impacketsmbclient/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string136 = /impacket\-smbclient/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string137 = /impacket\-smbserver/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string138 = /impacket\-ticketer/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string139 = /impacketutils/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself. Packets can be constructed from scratch. as well as parsed from raw data. and the object oriented API makes it simple to work with deep hierarchies of protocols. The library provides a set of tools as examples of what can be done within the context of this library
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string140 = /impacket\-wmiexec/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string141 = /ImpactDecoder/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string142 = /ImpactPacket/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string143 = /import\simpacket/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string144 = /is_kirbi_file/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string145 = /karmaSMB\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string146 = /kerberos\-ldap\-password\-hunter\.sh/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string147 = /kerberosv5\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string148 = /keylistattack\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string149 = /kintercept\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string150 = /kintercept\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/dirkjanm/krbrelayx
        $string151 = /krbrelayx/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string152 = /ldapasn1\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string153 = /ldapattack\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string154 = /LDAP\-Password\-Hunter/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string155 = /ldaprelayclient\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string156 = /loadKirbiFile/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string157 = /lookupsid\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string158 = /mimikatz\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string159 = /mimilib\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string160 = /mqtt_check\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string161 = /mssqlattack\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string162 = /mssqlrelayclient\./ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string163 = /ndDelegation\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string164 = /netview\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string165 = /nmapAnswerMachine\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string166 = /ntfs\-read\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string167 = /ntlm\.py\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string168 = /ntlmrelayx\./ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string169 = /package\=impacket/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string170 = /pcap_linktypes\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string171 = /pcapfile\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string172 = /Permits\sto\sbackup\sa\sDACL\sbefore\sa\smodification/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string173 = /psexec\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string174 = /raiseChild\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string175 = /rawrelayserver\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string176 = /rbcd\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string177 = /rdp_check\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string178 = /registry\-read\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string179 = /relay.{0,1000}\/utils\/enum\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string180 = /rpcattack\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string181 = /rpcdump\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string182 = /rpcmap\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string183 = /rpcrelayclient\./ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string184 = /sambaPipe\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string185 = /samrdump\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string186 = /secretsdump\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string187 = /smbattack\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string188 = /smbexec\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string189 = /smbpasswd\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string190 = /smbrelayclient\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string191 = /smbrelayserver\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string192 = /smbrelayx\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string193 = /smbserver\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string194 = /smtprelayclient\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string195 = /sniffer\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string196 = /tcpshell\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string197 = /test_ccache_fromKirbi/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string198 = /ticketConverter\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string199 = /ticketer\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string200 = /wcfrelayserver\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string201 = /winregistry\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string202 = /wmipersist\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string203 = /Impacket\s/ nocase ascii wide

    condition:
        any of them
}

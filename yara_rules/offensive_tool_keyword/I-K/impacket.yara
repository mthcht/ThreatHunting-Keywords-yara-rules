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
        $string1 = /\s\/Q\s\/C\s\>1\s\\\\127\.0\.01\\ADMIN\$\\__/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string2 = /\sdacledit\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string3 = /\s\-dc\-ip\s.{0,1000}\s\s\-so\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string4 = /\s\-dc\-ip\s.{0,1000}\s\-computer\-pass\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string5 = /\s\-dc\-ip\s.{0,1000}\s\-impersonate\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string6 = /\s\-dc\-ip\s.{0,1000}\s\-target\-ip\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket/blob/master/examples/getST.py
        $string7 = /\s\-force\-forwardable/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string8 = /\s\-hashes\s.{0,1000}\s\-spn\s.{0,1000}\s\-impersonate\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string9 = /\simpacket/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string10 = /\simpacket\// nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket/blob/master/examples/getST.py
        $string11 = /\s\-impersonate.{0,1000}\s\-hashes/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string12 = /\s\-just\-dc\-ntlm\s\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string13 = /\s\-just\-dc\-user\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string14 = /\s\-k\s\-request\-user\s.{0,1000}\s\-dc\-ip/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string15 = /\sLMHASH\:NTHASH/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string16 = /\s\-no\-pass\s\-usersfile\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string17 = /\s\-ntds\s.{0,1000}\.dit\s.{0,1000}\-system\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string18 = /\s\-ntds\sntds\.dit\s\-system\sSYSTEM\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string19 = /\s\-nthash\s.{0,1000}\s\-domain\-sid\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string20 = /\sntlm\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/LuemmelSec/ntlmrelayx.py_to_exe
        $string21 = /\sntlmrelayx\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket/blob/master/examples/getST.py
        $string22 = /\sPrincipalsAllowedToDelegateToAccount\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference
        $string23 = /\s\-sam\s.{0,1000}\s\-system\s.{0,1000}\s\-security\s.{0,1000}\sLOCAL\s\>\s.{0,1000}\.out/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string24 = /\s\-\-shadow\-credentials\s\-\-shadow\-target\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket/blob/master/examples/getST.py
        $string25 = /\s\-spn\scifs\/.{0,1000}\s\-hashes/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string26 = /\s\-system\sSYSTEM\s\-ntds\sNTDS\.dit\sLOCAL/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string27 = /\s\-system\sSYSTEM\s\-ntds\sNTDS\.dit\s\-outputfile/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string28 = /\s\-target\-domain\s.{0,1000}\s\-outputfile\s.{0,1000}\s\-no\-pass/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string29 = /\.py\s.{0,1000}\s\-k\s\-no\-pass/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string30 = /\/atexec\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string31 = /\/attacks\/.{0,1000}\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string32 = /\/Certipy\.exe/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string33 = /\/dacledit\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string34 = /\/exchanger\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string35 = /\/getST\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string36 = /\/impacket\./ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string37 = /\/impacket\// nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string38 = /\/kerberos\-ldap\-password\-hunter/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string39 = /\/krb5\/.{0,1000}\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string40 = /\/ldap\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string41 = /\/lookupsid\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string42 = /\/ntlm\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string43 = /\/ntlmrelayx\.exe/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/LuemmelSec/ntlmrelayx.py_to_exe
        $string44 = /\/ntlmrelayx\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string45 = /\/ping6\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string46 = /\/secretsdump\.exe/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string47 = /\/smb\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string48 = /\/SMB_RPC\/.{0,1000}\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string49 = /\/smb3\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string50 = /\/sniff\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string51 = /\/winregistry\.py.{0,1000}/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string52 = /\:9090.{0,1000}\/api\/v1\.0\/relays/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string53 = /\?convert_ccache_to_kirbi/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string54 = /\?convert_kirbi_to_ccache/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string55 = /\\\$.{0,1000}\.kirbi/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string56 = /\\\\127\.0\.0\.1\\c\$/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string57 = /\\Certipy\.exe/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string58 = /\\dacledit\-.{0,1000}\.bak/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string59 = /\\dacledit\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string60 = /\\impacket\./ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string61 = /\\krb5\\.{0,1000}\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string62 = /\\ntlm\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string63 = /\\ntlmrelayx\.exe/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/LuemmelSec/ntlmrelayx.py_to_exe
        $string64 = /\\ntlmrelayx\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string65 = /\\secretsdump\.exe/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string66 = /\\SMB_RPC\\.{0,1000}\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string67 = /\\sniff\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string68 = /41414141\-4141\-4141\-4141\-414141414141/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string69 = /455a5ed5b8aca163fd8bbc11a06de8b652517c50a32c634f33a6a093d47e3d4e/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string70 = /5f8c475f1a4772644bbae8e3a31e11e78b7f44a1559f5e6bb58b7b3b9083323d/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string71 = /831d70eff6225d3ca5ed5723f7d17c5b7f7f7aaad583e6b0a7d8dd99cdcde755/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string72 = /adcsattack\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string73 = /addcomputer\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string74 = /admin\.kirbi/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string75 = /atexec\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string76 = /cat\s.{0,1000}\.ntds/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string77 = /changepasswd\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string78 = /cmd\.exe\s\/C\stasklist\s\/m\s\>\sC\:\\Windows\\Temp\\.{0,1000}\.tmp\s2\>\&1/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string79 = /cmd\.exe\s\/Q\s\/c\s.{0,1000}\s1\>\s.{0,1000}\\\\127\.0\.0\.1\\ADMIN\$\\__.{0,1000}\s2\>\&1/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string80 = /cmd\.exe\s\/Q\s\/c\scd\s\s1\>\s\\\\127\.0\.0\.1\\ADMIN\$\\_.{0,1000}\>\&1/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string81 = /cmd\.exe\s\/Q\s\/c\scd\s\\\s1\>\s\\\\127\.0\.0\.1\\ADMIN\$\\__.{0,1000}\s2\>\&1/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string82 = /cmd\.exe\s\/Q\s\/c\secho\stasklist\s\^\>\s\\\\127\.0\.0\.1\\C\$\\__.{0,1000}2\^\>\^\&1\s\>\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string83 = /cmd\.exe\s\/Q\s\/c\swhoami\s1\>\s\\\\127\.0\.0\.1\\ADMIN\$\\_.{0,1000}2\>\&1/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string84 = /cmd\.exe\"\s\/C\stasklist\s\/m\s\>\sC\:\\Windows\\Temp\\.{0,1000}\.tmp\s2\>\&1/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string85 = /cmd\.exe\"\s\/Q\s\/c\scd\s\s1\>\s\\\\127\.0\.0\.1\\ADMIN\$\\_.{0,1000}\>\&1/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string86 = /cmd\.exe\"\s\/Q\s\/c\scd\s\\\s1\>\s\\\\127\.0\.0\.1\\ADMIN\$\\__.{0,1000}\s2\>\&1/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string87 = /cmd\.exe\"\s\/Q\s\/c\swhoami\s1\>\s\\\\127\.0\.0\.1\\ADMIN\$\\_.{0,1000}2\>\&1/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string88 = /db8b7152534b483ed966cd9557bed083106b448feea5e06d6963c0bd7b282f40/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string89 = /dcomexec\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string90 = /dcsyncattack\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string91 = /dcsyncclient\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string92 = /dpapi\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string93 = /DumpNTLMInfo\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string94 = /e58b8ccccb9d997328877f89fa748bc62b4c4b29945abd2a1d8d60b55a84811a/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string95 = /e97d6c8f6d2fc73bceefac93fdfa2c4724a68e58b26e4c2631e78580f2722d2a/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/LuemmelSec/ntlmrelayx.py_to_exe
        $string96 = /e97d6c8f6d2fc73bceefac93fdfa2c4724a68e58b26e4c2631e78580f2722d2a/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string97 = /examples\/netview\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string98 = /f4257657ae5bf141b31cd56db96ac003687be4eb404d1245e27256307e0b5d35/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string99 = /findDelegation\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket/blob/master/examples/getST.py
        $string100 = /\-force\-forwardableet\-ADComputer/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string101 = /fortra\/impacket/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string102 = /FrameManagementAssociationRequest\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string103 = /FrameManagementDeauthentication\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string104 = /FrameManagementProbeRequest\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string105 = /FrameManagementReassociationResponse\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string106 = /GetADUsers\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string107 = /Get\-GPPPassword\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string108 = /GetNPUsers\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string109 = /getPac\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string110 = /getTGT\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string111 = /GetUserSPNs\./ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string112 = /goldenPac\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string113 = /http\:\/\/127\.0\.0\.1\:9090\// nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string114 = /http\:\/\/localhost\:9090\// nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string115 = /httpattack\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string116 = /httpattacks\/.{0,1000}\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string117 = /httprelayclient\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string118 = /httprelayserver\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string119 = /imapattack\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string120 = /imaprelayclient\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself. Packets can be constructed from scratch. as well as parsed from raw data. and the object oriented API makes it simple to work with deep hierarchies of protocols. The library provides a set of tools as examples of what can be done within the context of this library
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string121 = /impacket/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself. Packets can be constructed from scratch. as well as parsed from raw data. and the object oriented API makes it simple to work with deep hierarchies of protocols. The library provides a set of tools as examples of what can be done within the context of this library.
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string122 = /impacket/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string123 = /impacket\-.{0,1000}\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string124 = /impacket\-.{0,1000}\.tar\.gz/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string125 = /\'impacket\./ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string126 = /impacket\.git/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string127 = /impacket\.krb5\.asn1/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string128 = /impacket\.krb5\.ccache/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string129 = /impacket\.krb5\.kerberosv5/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string130 = /impacket\.ldap/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string131 = /impacket\.msada_guids/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string132 = /impacket\.ntlm/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string133 = /impacket\/.{0,1000}\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string134 = /impacket\:latest/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string135 = /impacket__init__/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string136 = /impacket\-atexec/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string137 = /impacket\-dcomexec/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string138 = /impacket\-GetADUsers/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string139 = /impacket\-GetNPUsers/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string140 = /impacket\-getST/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string141 = /impacket\-getTGT/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string142 = /impacketldap_shell/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string143 = /impacketlogger/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string144 = /impacket\-lookupsid/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string145 = /impacketmssqlshell/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string146 = /impacket\-netview/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string147 = /impacketntlmrelayx/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string148 = /impacketos_ident/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string149 = /impacket\-psexec/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string150 = /impacket\-reg/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself. Packets can be constructed from scratch. as well as parsed from raw data. and the object oriented API makes it simple to work with deep hierarchies of protocols. The library provides a set of tools as examples of what can be done within the context of this library
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string151 = /impacket\-reg/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string152 = /impacketremcomsvc/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string153 = /impacketrpcdatabase/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string154 = /impacket\-rpcdump/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string155 = /impacket\-samrdump/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string156 = /impacketsecretsdump/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference
        $string157 = /impacket\-secretsdump/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string158 = /impacket\-secretsdump/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string159 = /impacketserviceinstall/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string160 = /impacket\-services/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string161 = /impacketsmbclient/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string162 = /impacket\-smbclient/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string163 = /impacket\-smbserver/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string164 = /impacket\-ticketer/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string165 = /impacketutils/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself. Packets can be constructed from scratch. as well as parsed from raw data. and the object oriented API makes it simple to work with deep hierarchies of protocols. The library provides a set of tools as examples of what can be done within the context of this library
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string166 = /impacket\-wmiexec/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string167 = /ImpactDecoder/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string168 = /ImpactPacket/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string169 = /import\simpacket/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string170 = /is_kirbi_file/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string171 = /karmaSMB\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string172 = /kerberos\-ldap\-password\-hunter\.sh/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string173 = /kerberosv5\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string174 = /keylistattack\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string175 = /kintercept\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string176 = /kintercept\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/dirkjanm/krbrelayx
        $string177 = /krbrelayx/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string178 = /ldapasn1\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string179 = /ldapattack\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/oldboy21/LDAP-Password-Hunter
        $string180 = /LDAP\-Password\-Hunter/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string181 = /ldaprelayclient\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string182 = /loadKirbiFile/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string183 = /lookupsid\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string184 = /mimikatz\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string185 = /mimilib\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string186 = /mqtt_check\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string187 = /mssqlattack\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string188 = /mssqlrelayclient\./ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string189 = /ndDelegation\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string190 = /netview\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string191 = /nmapAnswerMachine\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string192 = /ntfs\-read\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string193 = /ntlm\.py\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string194 = /ntlmrelayx\./ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/LuemmelSec/ntlmrelayx.py_to_exe
        $string195 = /ntlmrelayx\.exe/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/LuemmelSec/ntlmrelayx.py_to_exe
        $string196 = /ntlmrelayx\.py_to_exe/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/LuemmelSec/ntlmrelayx.py_to_exe
        $string197 = /ntlmrelayx_original\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string198 = /package\=impacket/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string199 = /pcap_linktypes\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string200 = /pcapfile\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string201 = /Permits\sto\sbackup\sa\sDACL\sbefore\sa\smodification/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string202 = /psexec\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string203 = /raiseChild\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string204 = /rawrelayserver\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string205 = /rbcd\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string206 = /rdp_check\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string207 = /registry\-read\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string208 = /relay.{0,1000}\/utils\/enum\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string209 = /rpcattack\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string210 = /rpcdump\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string211 = /rpcmap\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string212 = /rpcrelayclient\./ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string213 = /sambaPipe\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string214 = /samrdump\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string215 = /secretsdump\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string216 = /smbattack\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string217 = /smbexec\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string218 = /smbpasswd\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string219 = /smbrelayclient\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string220 = /smbrelayserver\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string221 = /smbrelayx\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string222 = /smbserver\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string223 = /smtprelayclient\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string224 = /sniffer\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string225 = /tcpshell\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string226 = /test_ccache_fromKirbi/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string227 = /ticketConverter\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string228 = /ticketer\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string229 = /wcfrelayserver\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/SecureAuthCorp/impacket
        $string230 = /winregistry\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string231 = /wmipersist\.py/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string232 = /Impacket\s/ nocase ascii wide

    condition:
        any of them
}

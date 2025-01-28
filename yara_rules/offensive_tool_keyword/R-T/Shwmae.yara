rule Shwmae
{
    meta:
        description = "Detection patterns for the tool 'Shwmae' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Shwmae"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Shwmae is a tool focused on Windows Hello and DPAPI exploitation. It enables the enumeration - extraction and manipulation of Windows Hello keys and credentials
        // Reference: https://github.com/CCob/Shwmae
        $string1 = "\"author\": \"@_EthicalChaos_\"" nocase ascii wide
        // Description: Shwmae is a tool focused on Windows Hello and DPAPI exploitation. It enables the enumeration - extraction and manipulation of Windows Hello keys and credentials
        // Reference: https://github.com/CCob/Shwmae
        $string2 = /\.exe\sdump\s\-\-key\-name\s/ nocase ascii wide
        // Description: Shwmae is a tool focused on Windows Hello and DPAPI exploitation. It enables the enumeration - extraction and manipulation of Windows Hello keys and credentials
        // Reference: https://github.com/CCob/Shwmae
        $string3 = /\/Shwmae\.exe/ nocase ascii wide
        // Description: Shwmae is a tool focused on Windows Hello and DPAPI exploitation. It enables the enumeration - extraction and manipulation of Windows Hello keys and credentials
        // Reference: https://github.com/CCob/Shwmae
        $string4 = /\/Shwmae\.git/ nocase ascii wide
        // Description: Shwmae is a tool focused on Windows Hello and DPAPI exploitation. It enables the enumeration - extraction and manipulation of Windows Hello keys and credentials
        // Reference: https://github.com/CCob/Shwmae
        $string5 = "/shwmae/keys" nocase ascii wide
        // Description: Shwmae is a tool focused on Windows Hello and DPAPI exploitation. It enables the enumeration - extraction and manipulation of Windows Hello keys and credentials
        // Reference: https://github.com/CCob/Shwmae
        $string6 = /\/webauthn\-inject\.js/ nocase ascii wide
        // Description: Shwmae is a tool focused on Windows Hello and DPAPI exploitation. It enables the enumeration - extraction and manipulation of Windows Hello keys and credentials
        // Reference: https://github.com/CCob/Shwmae
        $string7 = /\[\!\]\sFailed\sto\sget\sprivileges\swhen\strying\sto\sgain\sSYSTEM/ nocase ascii wide
        // Description: Shwmae is a tool focused on Windows Hello and DPAPI exploitation. It enables the enumeration - extraction and manipulation of Windows Hello keys and credentials
        // Reference: https://github.com/CCob/Shwmae
        $string8 = /\[\+\]\sDecrypted\sSYSTEM\svault\spolicy/ nocase ascii wide
        // Description: Shwmae is a tool focused on Windows Hello and DPAPI exploitation. It enables the enumeration - extraction and manipulation of Windows Hello keys and credentials
        // Reference: https://github.com/CCob/Shwmae
        $string9 = /\[\+\]\sSuccessfully\sdecrypted\sNGC\skey\sset\sfrom\sprotector\stype\s/ nocase ascii wide
        // Description: Shwmae is a tool focused on Windows Hello and DPAPI exploitation. It enables the enumeration - extraction and manipulation of Windows Hello keys and credentials
        // Reference: https://github.com/CCob/Shwmae
        $string10 = /\\Shwmae\.exe/ nocase ascii wide
        // Description: Shwmae is a tool focused on Windows Hello and DPAPI exploitation. It enables the enumeration - extraction and manipulation of Windows Hello keys and credentials
        // Reference: https://github.com/CCob/Shwmae
        $string11 = /\\webauthn\-inject\.js/ nocase ascii wide
        // Description: Shwmae is a tool focused on Windows Hello and DPAPI exploitation. It enables the enumeration - extraction and manipulation of Windows Hello keys and credentials
        // Reference: https://github.com/CCob/Shwmae
        $string12 = "1bb41d5d6d3c883be23682ec1d94ee3317c0ab8d5fa2bee3712a5f33c0d6960b" nocase ascii wide
        // Description: Shwmae is a tool focused on Windows Hello and DPAPI exploitation. It enables the enumeration - extraction and manipulation of Windows Hello keys and credentials
        // Reference: https://github.com/CCob/Shwmae
        $string13 = "228eb663a1c8bfc0f6a05ba522038844c762319961b07e5b623dcfa8e30ce5fa" nocase ascii wide
        // Description: Shwmae is a tool focused on Windows Hello and DPAPI exploitation. It enables the enumeration - extraction and manipulation of Windows Hello keys and credentials
        // Reference: https://github.com/CCob/Shwmae
        $string14 = "5D3EF551-3D1F-468E-A75B-764F436D577D" nocase ascii wide
        // Description: Shwmae is a tool focused on Windows Hello and DPAPI exploitation. It enables the enumeration - extraction and manipulation of Windows Hello keys and credentials
        // Reference: https://github.com/CCob/Shwmae
        $string15 = "c97e849bf283c760811373be29c588adc6ad820d7695a7552e87be693bea0ee6" nocase ascii wide
        // Description: Shwmae is a tool focused on Windows Hello and DPAPI exploitation. It enables the enumeration - extraction and manipulation of Windows Hello keys and credentials
        // Reference: https://github.com/CCob/Shwmae
        $string16 = "CCob/Shwmae" nocase ascii wide
        // Description: Shwmae is a tool focused on Windows Hello and DPAPI exploitation. It enables the enumeration - extraction and manipulation of Windows Hello keys and credentials
        // Reference: https://github.com/CCob/Shwmae
        $string17 = "Forwards WebAuthn assertion requests to a compromised host running the Shwmae Windows Hello abuse tool" nocase ascii wide
        // Description: Shwmae is a tool focused on Windows Hello and DPAPI exploitation. It enables the enumeration - extraction and manipulation of Windows Hello keys and credentials
        // Reference: https://github.com/CCob/Shwmae
        $string18 = "ijacbjjjpmhencpkoghphdgbooifplmn" nocase ascii wide
        // Description: Shwmae is a tool focused on Windows Hello and DPAPI exploitation. It enables the enumeration - extraction and manipulation of Windows Hello keys and credentials
        // Reference: https://github.com/CCob/Shwmae
        $string19 = "Shwmae dump " nocase ascii wide
        // Description: Shwmae is a tool focused on Windows Hello and DPAPI exploitation. It enables the enumeration - extraction and manipulation of Windows Hello keys and credentials
        // Reference: https://github.com/CCob/Shwmae
        $string20 = "Shwmae enum " nocase ascii wide
        // Description: Shwmae is a tool focused on Windows Hello and DPAPI exploitation. It enables the enumeration - extraction and manipulation of Windows Hello keys and credentials
        // Reference: https://github.com/CCob/Shwmae
        $string21 = "Shwmae prt " nocase ascii wide
        // Description: Shwmae is a tool focused on Windows Hello and DPAPI exploitation. It enables the enumeration - extraction and manipulation of Windows Hello keys and credentials
        // Reference: https://github.com/CCob/Shwmae
        $string22 = "Shwmae prt " nocase ascii wide
        // Description: Shwmae is a tool focused on Windows Hello and DPAPI exploitation. It enables the enumeration - extraction and manipulation of Windows Hello keys and credentials
        // Reference: https://github.com/CCob/Shwmae
        $string23 = "Shwmae sign " nocase ascii wide
        // Description: Shwmae is a tool focused on Windows Hello and DPAPI exploitation. It enables the enumeration - extraction and manipulation of Windows Hello keys and credentials
        // Reference: https://github.com/CCob/Shwmae
        $string24 = "Shwmae webauthn " nocase ascii wide
        // Description: Shwmae is a tool focused on Windows Hello and DPAPI exploitation. It enables the enumeration - extraction and manipulation of Windows Hello keys and credentials
        // Reference: https://github.com/CCob/Shwmae
        $string25 = "Shwmae webauthn" nocase ascii wide
        // Description: Shwmae is a tool focused on Windows Hello and DPAPI exploitation. It enables the enumeration - extraction and manipulation of Windows Hello keys and credentials
        // Reference: https://github.com/CCob/Shwmae
        $string26 = /Shwmae\.exe\ssign/ nocase ascii wide
        // Description: Shwmae is a tool focused on Windows Hello and DPAPI exploitation. It enables the enumeration - extraction and manipulation of Windows Hello keys and credentials
        // Reference: https://github.com/CCob/Shwmae
        $string27 = "WebAuthn proxy running" nocase ascii wide

    condition:
        any of them
}

rule DeadPotato
{
    meta:
        description = "Detection patterns for the tool 'DeadPotato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DeadPotato"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: DeadPotato is a windows privilege escalation utility from the Potato family of exploits leveraging the SeImpersonate right to obtain SYSTEM privileges
        // Reference: https://github.com/lypd0/DeadPotato
        $string1 = /\/DeadPotato\.git/ nocase ascii wide
        // Description: DeadPotato is a windows privilege escalation utility from the Potato family of exploits leveraging the SeImpersonate right to obtain SYSTEM privileges
        // Reference: https://github.com/lypd0/DeadPotato
        $string2 = "/releases/download/Binaries/DeadPotato" nocase ascii wide
        // Description: DeadPotato is a windows privilege escalation utility from the Potato family of exploits leveraging the SeImpersonate right to obtain SYSTEM privileges
        // Reference: https://github.com/lypd0/DeadPotato
        $string3 = /\\DeadPotato\\pipe\\epmapper/ nocase ascii wide
        // Description: DeadPotato is a windows privilege escalation utility from the Potato family of exploits leveraging the SeImpersonate right to obtain SYSTEM privileges
        // Reference: https://github.com/lypd0/DeadPotato
        $string4 = /\\GodPotato\\pipe\\epmapper/ nocase ascii wide
        // Description: DeadPotato is a windows privilege escalation utility from the Potato family of exploits leveraging the SeImpersonate right to obtain SYSTEM privileges
        // Reference: https://github.com/lypd0/DeadPotato
        $string5 = /\\Resources\\mimikatz\.exe/ nocase ascii wide
        // Description: DeadPotato is a windows privilege escalation utility from the Potato family of exploits leveraging the SeImpersonate right to obtain SYSTEM privileges
        // Reference: https://github.com/lypd0/DeadPotato
        $string6 = ">DeadPotato<" nocase ascii wide
        // Description: DeadPotato is a windows privilege escalation utility from the Potato family of exploits leveraging the SeImpersonate right to obtain SYSTEM privileges
        // Reference: https://github.com/lypd0/DeadPotato
        $string7 = "2AE886C3-3272-40BE-8D3C-EBAEDE9E61E1" nocase ascii wide
        // Description: DeadPotato is a windows privilege escalation utility from the Potato family of exploits leveraging the SeImpersonate right to obtain SYSTEM privileges
        // Reference: https://github.com/lypd0/DeadPotato
        $string8 = "3ef06f25d21583d9c1158704c593f3276a1056cf6d23f8c56d8dac84df5320de" nocase ascii wide
        // Description: DeadPotato is a windows privilege escalation utility from the Potato family of exploits leveraging the SeImpersonate right to obtain SYSTEM privileges
        // Reference: https://github.com/lypd0/DeadPotato
        $string9 = "92804faaab2175dc501d73e814663058c78c0a042675a8937266357bcfb96c50" nocase ascii wide
        // Description: DeadPotato is a windows privilege escalation utility from the Potato family of exploits leveraging the SeImpersonate right to obtain SYSTEM privileges
        // Reference: https://github.com/lypd0/DeadPotato
        $string10 = "99333bd2aadc9ebdbeb842981f1bb054f2102cdb94e77a0a8d7588cabaf70dc6" nocase ascii wide
        // Description: DeadPotato is a windows privilege escalation utility from the Potato family of exploits leveraging the SeImpersonate right to obtain SYSTEM privileges
        // Reference: https://github.com/lypd0/DeadPotato
        $string11 = "9cd007dd93a195546eec029470211689568df8c877fdc5faef1e03f942097a9b" nocase ascii wide
        // Description: DeadPotato is a windows privilege escalation utility from the Potato family of exploits leveraging the SeImpersonate right to obtain SYSTEM privileges
        // Reference: https://github.com/lypd0/DeadPotato
        $string12 = "9d1292d97f03943a54c41497f4b4e3186dea857a276f76954206e42f848fa30d" nocase ascii wide
        // Description: DeadPotato is a windows privilege escalation utility from the Potato family of exploits leveraging the SeImpersonate right to obtain SYSTEM privileges
        // Reference: https://github.com/lypd0/DeadPotato
        $string13 = "a1202bb8a90a635f6551b1733c4b777ee6abac7689dad8e7391e3ad01e3a370e" nocase ascii wide
        // Description: DeadPotato is a windows privilege escalation utility from the Potato family of exploits leveraging the SeImpersonate right to obtain SYSTEM privileges
        // Reference: https://github.com/lypd0/DeadPotato
        $string14 = "b32415b6a08d324394ac97c20a27b5f5bd2425f4f7caef7bf75b733c6fe5f2fb" nocase ascii wide
        // Description: DeadPotato is a windows privilege escalation utility from the Potato family of exploits leveraging the SeImpersonate right to obtain SYSTEM privileges
        // Reference: https://github.com/lypd0/DeadPotato
        $string15 = "c871b8811cc20f85aa417f598bd55d43d7ebac611c238c364c8ab41953efe321" nocase ascii wide
        // Description: DeadPotato is a windows privilege escalation utility from the Potato family of exploits leveraging the SeImpersonate right to obtain SYSTEM privileges
        // Reference: https://github.com/lypd0/DeadPotato
        $string16 = /deadpotato\.exe/ nocase ascii wide
        // Description: DeadPotato is a windows privilege escalation utility from the Potato family of exploits leveraging the SeImpersonate right to obtain SYSTEM privileges
        // Reference: https://github.com/lypd0/DeadPotato
        $string17 = /DeadPotato\-NET4\.exe/ nocase ascii wide
        // Description: DeadPotato is a windows privilege escalation utility from the Potato family of exploits leveraging the SeImpersonate right to obtain SYSTEM privileges
        // Reference: https://github.com/lypd0/DeadPotato
        $string18 = "ea36b8a42cc8ef052c4b58d29bdd20c5fe95dd8a025f8ac4728046891ef281bc" nocase ascii wide
        // Description: DeadPotato is a windows privilege escalation utility from the Potato family of exploits leveraging the SeImpersonate right to obtain SYSTEM privileges
        // Reference: https://github.com/lypd0/DeadPotato
        $string19 = /GodPotato\.exe/ nocase ascii wide
        // Description: DeadPotato is a windows privilege escalation utility from the Potato family of exploits leveraging the SeImpersonate right to obtain SYSTEM privileges
        // Reference: https://github.com/lypd0/DeadPotato
        $string20 = "lypd0/DeadPotato" nocase ascii wide
        // Description: DeadPotato is a windows privilege escalation utility from the Potato family of exploits leveraging the SeImpersonate right to obtain SYSTEM privileges
        // Reference: https://github.com/lypd0/DeadPotato
        $string21 = "ncacn_ip_tcp:fuck you !" nocase ascii wide

    condition:
        any of them
}

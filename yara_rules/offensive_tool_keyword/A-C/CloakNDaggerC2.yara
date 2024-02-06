rule CloakNDaggerC2
{
    meta:
        description = "Detection patterns for the tool 'CloakNDaggerC2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CloakNDaggerC2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A C2 framework designed around the use of public/private RSA key pairs to sign and authenticate commands being executed. This prevents MiTM interception of calls and ensures opsec during delicate operations.
        // Reference: https://github.com/matt-culbert/CloakNDaggerC2
        $string1 = /\/CloakNDaggerC2/ nocase ascii wide
        // Description: A C2 framework designed around the use of public/private RSA key pairs to sign and authenticate commands being executed. This prevents MiTM interception of calls and ensures opsec during delicate operations.
        // Reference: https://github.com/matt-culbert/CloakNDaggerC2
        $string2 = /\\CloakNDaggerC2/ nocase ascii wide
        // Description: A C2 framework designed around the use of public/private RSA key pairs to sign and authenticate commands being executed. This prevents MiTM interception of calls and ensures opsec during delicate operations.
        // Reference: https://github.com/matt-culbert/CloakNDaggerC2
        $string3 = /CloakNDaggerC2\-main/ nocase ascii wide
        // Description: A C2 framework designed around the use of public/private RSA key pairs to sign and authenticate commands being executed. This prevents MiTM interception of calls and ensures opsec during delicate operations.
        // Reference: https://github.com/matt-culbert/CloakNDaggerC2
        $string4 = /http\:\/\/192\.168\.1\.179\:8000\/session/ nocase ascii wide
        // Description: A C2 framework designed around the use of public/private RSA key pairs to sign and authenticate commands being executed. This prevents MiTM interception of calls and ensures opsec during delicate operations.
        // Reference: https://github.com/matt-culbert/CloakNDaggerC2
        $string5 = /nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4pz/ nocase ascii wide

    condition:
        any of them
}

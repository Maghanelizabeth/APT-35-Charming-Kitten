Detects scripts used to steal credentials via HTTP POST, form capture, or exfiltration to external domains.

rule APT35_Credential_Harvester_Script
{
    meta:
        description = "Detects credential harvesting scripts used in phishing chains"
        category = "Credential Theft"

    strings:
        $post1 = "POST" nocase
        $post2 = "fetch(" nocase
        $xhr1 = "XMLHttpRequest" nocase
        $cred1 = "password=" nocase
        $cred2 = "username=" nocase
        $exfil1 = "http://" nocase
        $exfil2 = "https://" nocase

    condition:
        2 of ($cred*) and 1 of ($post*, $xhr*) and 1 of ($exfil*)
}

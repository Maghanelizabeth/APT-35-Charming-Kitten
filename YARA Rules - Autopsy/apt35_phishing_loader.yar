Detects phishing-style HTML or script-based loaders commonly used in credential harvesting campaigns (fake login pages, redirect chains, embedded forms).

rule APT35_Phishing_Login_Loader
{
    meta:
        description = "Detects phishing login page behavior commonly associated with APT35 credential harvesting campaigns"
        author = "Threat Hunting Library"
        category = "Phishing / Credential Harvesting"

    strings:
        $html1 = "<form" nocase
        $html2 = "password" nocase
        $html3 = "username" nocase
        $html4 = "signin" nocase
        $js1 = "document.location" nocase
        $js2 = "window.location" nocase
        $js3 = "setTimeout" nocase

    condition:
        (3 of ($html*)) and 1 of ($js*)
}

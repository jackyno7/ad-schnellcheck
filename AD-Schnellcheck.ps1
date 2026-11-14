#Requires -Version 5.1
<#
.SYNOPSIS
    AD-Schnellcheck (free short edition of the AD audit report): checks an Active Directory in 8 points
    (password policy, administrators, user accounts, outdated operating systems) and writes an HTML report in English or German.

    The full version "AD Audit Report" checks 21 points (service accounts with admin rights, Kerberoasting targets,
    passwords in description fields, inactive accounts, krbtgt age, empty groups, AD recycle bin and more):
    https://mueller86.gumroad.com/l/fcneoc  or  https://www.etsy.com/shop/ITAdminToolsbyMM

    Deutsch: prüft ein Active Directory in 8 Punkten und erzeugt einen HTML-Bericht (Sprache wählbar mit -Language de|en).

.DESCRIPTION
    Vollversion mit weiteren Prüfpunkten: Etsy https://www.etsy.com/listing/4588853943 oder Gumroad https://mueller86.gumroad.com/l/fcneoc
    Alle Skripte und Vorlagen: https://github.com/jackyno7

    The script is strictly READ-ONLY. It changes nothing in Active Directory, creates nothing, deletes nothing and
    transmits no data. It writes exactly one HTML file (and CSV files on request) to the given output folder.
    The report language follows the Windows display language (German or English) and can be set with -Language.

    Requirements: Windows PowerShell 5.1, the "ActiveDirectory" module (present on domain controllers, otherwise RSAT
    "Active Directory Domain Services and Lightweight Directory Services Tools") and a domain account with read rights.
    Administrator rights are not required.

    Deutsch: Das Skript arbeitet ausschließlich LESEND und überträgt keine Daten. Es schreibt genau eine HTML-Datei
    (auf Wunsch CSV-Dateien). Voraussetzungen: Windows PowerShell 5.1, Modul "ActiveDirectory", Domänenkonto mit Leserechten.

.PARAMETER Output
    Path of the HTML file. Default: AD-Schnellcheck_<domain>_<date>.html in the current folder. (Alias: Ausgabe)

.PARAMETER MaxAdmins
    From how many privileged accounts onward the count is flagged (default 5).

.PARAMETER Server
    A specific domain controller or domain (optional).

.PARAMETER Credential
    Credentials of a domain account (Get-Credential) if the script does not run as a domain user, for example from a
    computer outside the domain. Then also specify -Server. (Alias: Anmeldung)

.PARAMETER Csv
    Additionally writes one CSV file per check with findings next to the report.

.PARAMETER NoOpen
    Does not open the finished report in the browser. (Alias: NichtOeffnen)

.PARAMETER PassThru
    Additionally returns the findings as objects (for your own analysis).

.PARAMETER Language
    Report and console language: de or en. Default: German on a German Windows, otherwise English.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\AD-Schnellcheck.ps1

.EXAMPLE
    .\AD-Schnellcheck.ps1 -Csv -Output C:\Reports\ad.html -Language en

.NOTES
    IT Admin Tools by MM - AD-Schnellcheck Version 1.1 (11.2026), license: MIT (see LICENSE)
    Not a substitute for a security audit. Use at your own risk. / Kein Ersatz für eine Sicherheitsprüfung. Nutzung auf eigene Verantwortung.
#>
[CmdletBinding()]
param(
    [Alias('Ausgabe')][string]$Output,
    [ValidateRange(1, 1000)][int]$MaxAdmins = 5,
    [string]$Server,
    [Alias('Anmeldung')][System.Management.Automation.PSCredential]$Credential,
    [switch]$Csv,
    [Alias('NichtOeffnen')][switch]$NoOpen,
    [switch]$PassThru,
    [ValidateSet('de', 'en')][string]$Language = $(if ((Get-UICulture).TwoLetterISOLanguageName -eq 'de') { 'de' } else { 'en' })
)

$ErrorActionPreference = 'Stop'
$Version = '1.1'
$En = ($Language -eq 'en')
# T 'deutsch' 'english': liefert den Text in der gewählten Sprache / returns the text in the chosen language
function T([string]$de, [string]$en) { if ($script:En) { $en } else { $de } }

# CSV files open in Excel and values starting with = + - @ would run as formulas (names of files, folders, accounts and computers come from users).
# This function replaces Export-Csv for this script and prefixes such values with an apostrophe.
# (Deutsch) CSV-Dateien öffnen sich in Excel: Werte, die mit = + - @ beginnen, würden dort als Formel ausgeführt (Namen von Dateien, Ordnern, Konten oder Computern
# stammen von Benutzern). Diese Funktion ersetzt für dieses Skript den Befehl Export-Csv und setzt vor solche Werte ein Hochkomma.
function Export-Csv {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline = $true)]$InputObject, [Parameter(Mandatory)][string]$Path, [switch]$NoTypeInformation, [string]$Delimiter = ';', [string]$Encoding = 'UTF8')
    begin { $alle = New-Object System.Collections.Generic.List[object] }
    process { if ($null -ne $InputObject) { $alle.Add($InputObject) } }
    end {
        $sicher = foreach ($o in $alle) {
            $n = [ordered]@{}
            foreach ($p in $o.PSObject.Properties) { $v = $p.Value; if (($v -is [string]) -and ($v -match '^[=+@\t\r]|^-.')) { $v = "'" + $v }; $n[$p.Name] = $v }
            [pscustomobject]$n
        }
        $sicher | Microsoft.PowerShell.Utility\Export-Csv -Path $Path -NoTypeInformation:$NoTypeInformation -Delimiter $Delimiter -Encoding $Encoding
    }
}

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host (T 'Das PowerShell-Modul "ActiveDirectory" fehlt.' 'The PowerShell module "ActiveDirectory" is missing.') -ForegroundColor Red
    Write-Host (T 'Windows 10/11: Einstellungen > Optionale Features > "RSAT: Active Directory Domain Services" hinzufügen.' 'Windows 10/11: Settings > Optional features > add "RSAT: Active Directory Domain Services".')
    Write-Host 'Windows Server:  Install-WindowsFeature RSAT-AD-PowerShell'
    exit 2
}
Import-Module ActiveDirectory

$ad = @{}
if ($Server) { $ad.Server = $Server }
if ($Credential) { $ad.Credential = $Credential }

# ------------------------------------------------------------------ Hilfsfunktionen
function Datum($d, $leer = $null) { if ($null -eq $leer) { $leer = T 'nie' 'never' }; if ($d) { ([datetime]$d).ToString((T 'dd.MM.yyyy' 'yyyy-MM-dd')) } else { $leer } }
function JaNein($b) { if ($b) { T 'Ja' 'Yes' } else { T 'Nein' 'No' } }
function Ort($dn) { ($dn -replace '^CN=.+?(?<!\\),', '') -replace ',DC=.*$', '' }
function Html($t) { [System.Net.WebUtility]::HtmlEncode([string]$t) }

function BenutzerZeile($u, [hashtable]$Zusatz = @{}) {
    $z = [ordered]@{
        (T 'Konto' 'Account')                    = $u.SamAccountName
        Name                                     = $u.Name
        (T 'Aktiv' 'Enabled')                    = JaNein $u.Enabled
        (T 'Letzte Anmeldung' 'Last logon')      = Datum $u.LastLogonDate
        (T 'Kennwort gesetzt' 'Password set')    = Datum $u.PasswordLastSet
        (T 'Ort' 'Location')                     = Ort $u.DistinguishedName
    }
    foreach ($k in $Zusatz.Keys) { $z[$k] = $Zusatz[$k] }
    [pscustomobject]$z
}

$Befunde = New-Object System.Collections.Generic.List[object]
function Befund {
    param([string]$Id, [string]$Bereich, [string]$Titel, [ValidateSet('Hoch', 'Mittel', 'Niedrig', 'Info')][string]$Stufe,
        $Objekte, [string]$Erklaerung, [string]$Empfehlung)
    $liste = @($Objekte | Where-Object { $null -ne $_ })
    $status = $Stufe
    if ($liste.Count -eq 0 -and $Stufe -ne 'Info') { $status = 'OK' }
    $Befunde.Add([pscustomobject]@{
            Id = $Id; Bereich = $Bereich; Titel = $Titel; Stufe = $status; Anzahl = $liste.Count
            Objekte = $liste; Erklaerung = $Erklaerung; Empfehlung = $Empfehlung
        })
}

# ------------------------------------------------------------------ Daten lesen
Write-Host (T 'AD-Schnellcheck - es wird nur gelesen, nichts verändert.' 'AD-Schnellcheck - read-only, nothing is changed.') -ForegroundColor Cyan
Write-Host (T '  Domäne und Richtlinien ...' '  Domain and policies ...')
$dom = Get-ADDomain @ad
$wald = Get-ADForest @ad
$dn = $dom.DistinguishedName
$sid = $dom.DomainSID.Value
$richtlinie = Get-ADDefaultDomainPasswordPolicy @ad
$jetzt = Get-Date

Write-Host (T '  Benutzerkonten ...' '  User accounts ...')
$eig = 'Enabled', 'PasswordNeverExpires', 'PasswordNotRequired', 'AllowReversiblePasswordEncryption', 'DoesNotRequirePreAuth',
'ServicePrincipalName', 'LastLogonDate', 'PasswordLastSet', 'whenCreated', 'Description', 'MemberOf', 'AccountExpirationDate'
$alle = @(Get-ADUser -Filter * -Properties $eig @ad)
$krbtgt = $alle | Where-Object { $_.SID.Value -eq "$sid-502" }
$gast = $alle | Where-Object { $_.SID.Value -eq "$sid-501" }
# Eingebaute Sonderkonten (Gast, krbtgt, DefaultAccount) werden gesondert bzw. gar nicht bewertet
$benutzer = @($alle | Where-Object { $_.SID.Value -notmatch '-(501|502|503)$' })
$aktive = @($benutzer | Where-Object Enabled)

Write-Host (T '  Privilegierte Gruppen ...' '  Privileged groups ...')
$privSids = [ordered]@{
    "$sid-512"     = (T 'Domänen-Admins' 'Domain Admins')
    "$sid-519"     = (T 'Organisations-Admins' 'Enterprise Admins')
    "$sid-518"     = (T 'Schema-Admins' 'Schema Admins')
    'S-1-5-32-544' = (T 'Administratoren' 'Administrators')
    'S-1-5-32-548' = (T 'Konten-Operatoren' 'Account Operators')
    'S-1-5-32-549' = (T 'Server-Operatoren' 'Server Operators')
    'S-1-5-32-551' = (T 'Sicherungs-Operatoren' 'Backup Operators')
}
$privGruppen = @()
$privNichtGelesen = @()
foreach ($s in $privSids.Keys) {
    try { $g = Get-ADGroup -Identity $s -Properties member @ad; $privGruppen += [pscustomobject]@{ Sid = $s; Gruppe = $g; Anzeige = $g.Name } }
    catch {
        # Gruppen anderer Domänen (z. B. Organisations-Admins in einer untergeordneten Domäne) gibt es hier nicht; alles andere ist ein Lesefehler
        if ($_.Exception.GetType().Name -ne 'ADIdentityNotFoundException') { $privNichtGelesen += $privSids[$s] }
    }
}
$privDns = $privGruppen | ForEach-Object { $_.Gruppe.DistinguishedName }
# Mitglieder inklusive verschachtelter Gruppen (LDAP_MATCHING_RULE_IN_CHAIN), je Konto die Liste der Gruppen
$privVon = @{}
foreach ($p in $privGruppen) {
    $treffer = Get-ADUser -LDAPFilter "(memberOf:1.2.840.113556.1.4.1941:=$($p.Gruppe.DistinguishedName))" @ad
    foreach ($t in $treffer) {
        if (-not $privVon.ContainsKey($t.SamAccountName)) { $privVon[$t.SamAccountName] = New-Object System.Collections.Generic.List[string] }
        $privVon[$t.SamAccountName].Add($p.Anzeige)
    }
}
$privKonten = @($benutzer | Where-Object { $privVon.ContainsKey($_.SamAccountName) })
function PrivZeile($u) { BenutzerZeile $u @{ (T 'Privilegierte Gruppen' 'Privileged groups') = ($privVon[$u.SamAccountName] -join ', ') } }

Write-Host (T '  Gruppen und Computer ...' '  Groups and computers ...')
$gruppen = @(Get-ADGroup -Filter * -Properties member, isCriticalSystemObject, whenCreated @ad)
$computer = @(Get-ADComputer -Filter * -Properties Enabled, OperatingSystem, OperatingSystemVersion, LastLogonDate, whenCreated @ad)

# ------------------------------------------------------------------ Prüfungen
Write-Host (T '  Auswertung ...' '  Analysis ...')

# --- Kennwortrichtlinie
$r = @()
if ($richtlinie.MinPasswordLength -lt 12) { $r += [pscustomobject]@{ (T 'Einstellung' 'Setting') = (T 'Minimale Kennwortlänge' 'Minimum password length'); (T 'Ist' 'Current') = (T "$($richtlinie.MinPasswordLength) Zeichen" "$($richtlinie.MinPasswordLength) characters"); (T 'Empfohlen' 'Recommended') = (T 'mindestens 12 Zeichen' 'at least 12 characters') } }
if (-not $richtlinie.ComplexityEnabled) { $r += [pscustomobject]@{ (T 'Einstellung' 'Setting') = (T 'Komplexitätsanforderungen' 'Complexity requirements'); (T 'Ist' 'Current') = (T 'deaktiviert' 'disabled'); (T 'Empfohlen' 'Recommended') = (T 'aktiviert (oder lange Passphrasen erzwingen)' 'enabled (or enforce long passphrases)') } }
if ($richtlinie.PasswordHistoryCount -lt 10) { $r += [pscustomobject]@{ (T 'Einstellung' 'Setting') = (T 'Kennwortchronik' 'Password history'); (T 'Ist' 'Current') = (T "$($richtlinie.PasswordHistoryCount) Kennwörter" "$($richtlinie.PasswordHistoryCount) passwords"); (T 'Empfohlen' 'Recommended') = (T 'mindestens 10' 'at least 10') } }
if ($richtlinie.LockoutThreshold -eq 0) { $r += [pscustomobject]@{ (T 'Einstellung' 'Setting') = (T 'Kontosperrungsschwelle' 'Account lockout threshold'); (T 'Ist' 'Current') = (T 'keine Sperrung' 'no lockout'); (T 'Empfohlen' 'Recommended') = (T 'z. B. 10 Fehlversuche, 15 Minuten' 'e.g. 10 failed attempts, 15 minutes') } }
if ($richtlinie.ReversibleEncryptionEnabled) { $r += [pscustomobject]@{ (T 'Einstellung' 'Setting') = (T 'Umkehrbare Verschlüsselung' 'Reversible encryption'); (T 'Ist' 'Current') = (T 'aktiviert' 'enabled'); (T 'Empfohlen' 'Recommended') = (T 'deaktiviert' 'disabled') } }
$stufe = 'Mittel'
if ($richtlinie.MinPasswordLength -lt 8 -or $richtlinie.ReversibleEncryptionEnabled) { $stufe = 'Hoch' }
Befund 'R1' (T 'Kennwortrichtlinie' 'Password policy') (T 'Schwache Einstellungen in der Domänen-Kennwortrichtlinie' 'Weak settings in the domain password policy') $stufe $r `
    (T 'Die Standard-Kennwortrichtlinie der Domäne gilt für alle Konten, für die keine eigene Richtlinie festgelegt ist.' 'The default domain password policy applies to all accounts that have no policy of their own.') `
    (T 'Einstellungen in der Gruppenrichtlinie "Default Domain Policy" anpassen. Für Administratoren und Dienstkonten bei Bedarf eine strengere abgestufte Kennwortrichtlinie (Fine-Grained Password Policy) anlegen.' 'Adjust the settings in the "Default Domain Policy" group policy. For administrators and service accounts, create a stricter fine-grained password policy if needed.')

# --- Administratoren
$a = @()
if ($privKonten.Count -gt $MaxAdmins) { $a = $privKonten | Sort-Object SamAccountName | ForEach-Object { PrivZeile $_ } }
Befund 'A1' (T 'Administratoren' 'Administrators') (T "Mehr als $MaxAdmins privilegierte Konten ($($privKonten.Count))" "More than $MaxAdmins privileged accounts ($($privKonten.Count))") 'Mittel' $a `
    (T 'Jedes Konto in einer Administratorgruppe ist ein mögliches Einfallstor. Mitgezählt werden auch Konten, die über verschachtelte Gruppen Mitglied sind.' 'Every account in an administrator group is a possible entry point. Accounts that are members through nested groups are counted too.') `
    (T 'Liste durchgehen: Wer braucht die Rechte wirklich dauerhaft? Alltagskonten gehören nicht in Administratorgruppen - dafür getrennte Admin-Konten verwenden.' 'Go through the list: who really needs these rights permanently? Daily-use accounts do not belong in administrator groups - use separate admin accounts.')


Befund 'A4' (T 'Administratoren' 'Administrators') (T 'Privilegierte Konten, deren Kennwort nie abläuft' 'Privileged accounts whose password never expires') 'Hoch' `
($privKonten | Where-Object { $_.Enabled -and $_.PasswordNeverExpires } | ForEach-Object { PrivZeile $_ }) `
    (T 'Kennwörter von Administratorkonten, die nie ablaufen, bleiben oft jahrelang unverändert - auch nach Personalwechseln.' 'Passwords of administrator accounts that never expire often stay unchanged for years - even after staff changes.') `
    (T 'Option "Kennwort läuft nie ab" entfernen. Für das eingebaute Administrator-Konto ein langes Zufallskennwort setzen und sicher hinterlegen (Notfallkonto).' 'Remove the option "Password never expires". For the built-in Administrator account, set a long random password and store it safely (break-glass account).')


# Konten und Gruppen, die Exchange bzw. Windows-Rollen selbst anlegen und verwalten (keine Pflege durch den Administrator nötig)
$exchangeSystem = '^(HealthMailbox|SystemMailbox\{|FederatedEmail\.|DiscoverySearchMailbox|Migration\.8f3e7716)'
$exchangeOrte = 'CN=Monitoring Mailboxes,|OU=Microsoft Exchange Security Groups,|CN=Microsoft Exchange System Objects,'

# --- Benutzerkonten
Befund 'K1' (T 'Benutzerkonten' 'User accounts') (T 'Kennwort läuft nie ab' 'Password never expires') 'Mittel' `
($aktive | Where-Object { $_.PasswordNeverExpires -and -not $privVon.ContainsKey($_.SamAccountName) -and $_.SamAccountName -notmatch $exchangeSystem -and $_.DistinguishedName -notmatch $exchangeOrte } | ForEach-Object { BenutzerZeile $_ }) `
    (T 'Für diese aktiven Konten ist der Kennwortablauf abgeschaltet (privilegierte Konten stehen unter A4). Konten, die Exchange selbst anlegt und verwaltet (HealthMailbox, SystemMailbox u. ä.), sind ausgenommen.' 'Password expiry is turned off for these enabled accounts (privileged accounts are listed under A4). Accounts that Exchange creates and manages itself (HealthMailbox, SystemMailbox etc.) are excluded.') `
    (T 'Bei Personenkonten die Option entfernen. Bei Dienstkonten ist sie üblich - dann aber ein langes Zufallskennwort verwenden und das Konto dokumentieren.' 'For personal accounts, remove the option. It is common for service accounts - then use a long random password and document the account.')

Befund 'K2' (T 'Benutzerkonten' 'User accounts') (T 'Kennwort nicht erforderlich' 'Password not required') 'Hoch' `
($aktive | Where-Object PasswordNotRequired | ForEach-Object { BenutzerZeile $_ }) `
    (T 'Diese aktiven Konten dürfen ein leeres Kennwort haben - die Kennwortrichtlinie gilt für sie nicht. Deaktivierte Konten (z. B. Systemkonten von Exchange) sind ausgenommen.' 'These enabled accounts may have an empty password - the password policy does not apply to them. Disabled accounts (e.g. Exchange system accounts) are excluded.') `
    (T 'Option entfernen: Set-ADUser <Konto> -PasswordNotRequired $false, danach Kennwort neu setzen.' 'Remove the option: Set-ADUser <account> -PasswordNotRequired $false, then set a new password.')


Befund 'K4' (T 'Benutzerkonten' 'User accounts') (T 'Kerberos-Vorauthentifizierung abgeschaltet' 'Kerberos pre-authentication disabled') 'Hoch' `
($benutzer | Where-Object DoesNotRequirePreAuth | ForEach-Object { BenutzerZeile $_ }) `
    (T 'Für diese Konten kann jeder im Netz ohne Anmeldung Daten abrufen, mit denen sich das Kennwort offline erraten lässt (AS-REP-Roasting).' 'For these accounts anyone on the network can request data without logging in that allows guessing the password offline (AS-REP roasting).') `
    (T 'Option "Keine Kerberos-Vorauthentifizierung erforderlich" entfernen.' 'Remove the option "Do not require Kerberos preauthentication".')


$g = @()
if ($gast -and $gast.Enabled) { $g = BenutzerZeile $gast }
Befund 'K10' (T 'Benutzerkonten' 'User accounts') (T 'Gastkonto ist aktiviert' 'Guest account is enabled') 'Hoch' $g `
    (T 'Über das Gastkonto ist eine Anmeldung ohne persönliches Konto möglich.' 'The guest account allows signing in without a personal account.') (T 'Gastkonto deaktivieren.' 'Disable the guest account.')


# --- Computer
# Windows 10 (ohne LTSC/IoT, deren Support länger läuft) ist seit dem 14.10.2025 ohne Sicherheitsupdates, außer mit bezahlten Erweiterten Sicherheitsupdates (ESU)
$altMuster = 'Windows (XP|Vista|7|8|8\.1)( |$)|Windows 10(?!.*(LTS[CB]|IoT))|Windows 2000|Windows NT|Server.? (2000|2003|2008|2012)'
Befund 'C1' (T 'Computer' 'Computers') (T 'Computer mit nicht mehr unterstütztem Betriebssystem' 'Computers with an unsupported operating system') 'Hoch' `
($computer | Where-Object { $_.Enabled -and $_.OperatingSystem -match $altMuster } | Sort-Object Name |
    ForEach-Object { [pscustomobject]@{ Computer = $_.Name; (T 'Betriebssystem' 'Operating system') = $_.OperatingSystem; (T 'Letzte Anmeldung' 'Last logon') = Datum $_.LastLogonDate; (T 'Ort' 'Location') = Ort $_.DistinguishedName } }) `
    (T 'Für diese Systeme gibt es keine Sicherheitsupdates mehr (Windows 10 nur noch mit kostenpflichtigen Erweiterten Sicherheitsupdates). Grundlage ist der im Verzeichnis eingetragene Betriebssystemname.' 'These systems no longer receive security updates (Windows 10 only with paid Extended Security Updates). The basis is the operating system name stored in the directory.') `
    (T 'Systeme ablösen oder vom Netz trennen. Wenn das Gerät nicht mehr existiert: Computerkonto löschen.' 'Replace these systems or disconnect them from the network. If the device no longer exists, delete the computer account.')


# ------------------------------------------------------------------ Bericht
Write-Host (T '  Bericht schreiben ...' '  Writing report ...')
if (-not $Output) { $Output = Join-Path (Get-Location).Path ("AD-Schnellcheck_{0}_{1:yyyy-MM-dd_HHmm}.html" -f $dom.DNSRoot, $jetzt) }
$Output = [System.IO.Path]::GetFullPath($Output)
$ordner = Split-Path $Output -Parent
if (-not (Test-Path $ordner)) { New-Item -ItemType Directory -Path $ordner -Force | Out-Null }

$stufeText = @{ Hoch = (T 'Hoch' 'High'); Mittel = (T 'Mittel' 'Medium'); Niedrig = (T 'Niedrig' 'Low'); Info = 'Info'; OK = 'OK' }
$rang = @{ Hoch = 0; Mittel = 1; Niedrig = 2; Info = 3; OK = 4 }
$zahl = @{}
foreach ($s in 'Hoch', 'Mittel', 'Niedrig', 'OK') { $zahl[$s] = @($Befunde | Where-Object Stufe -eq $s).Count }

$wer = "$env:USERDOMAIN\$env:USERNAME"
if ($Credential) { $wer = $Credential.UserName }

$css = @'
body{font-family:Segoe UI,Arial,sans-serif;color:#2b2f36;margin:0;background:#f4f6fa}
.seite{max-width:1100px;margin:0 auto;padding:28px 24px 60px}
h1{color:#1f5fae;margin:0 0 4px;font-size:28px} h2{color:#1f5fae;font-size:19px;margin:34px 0 10px;border-bottom:2px solid #d0d5dd;padding-bottom:6px}
.meta{color:#6b7280;font-size:13px;margin-bottom:22px}
.kacheln{display:flex;gap:14px;flex-wrap:wrap;margin:18px 0}
.kachel{flex:1;min-width:150px;background:#fff;border-radius:10px;padding:14px 18px;border-left:8px solid #999;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.kachel b{display:block;font-size:30px} .kachel span{font-size:13px;color:#6b7280}
table{border-collapse:collapse;width:100%;background:#fff;font-size:13px;margin:8px 0 4px}
th{background:#1f5fae;color:#fff;text-align:left;padding:7px 9px;font-weight:600} td{padding:6px 9px;border-bottom:1px solid #e5e7eb;vertical-align:top}
tr:nth-child(even) td{background:#f9fafb}
.marke{display:inline-block;min-width:58px;text-align:center;padding:2px 9px;border-radius:11px;color:#fff;font-size:12px;font-weight:600}
.m-Hoch{background:#d92d20}.m-Mittel{background:#f79009}.m-Niedrig{background:#ca8a04}.m-OK{background:#12b76a}.m-Info{background:#1f5fae}
.befund{background:#fff;border-radius:10px;padding:16px 20px;margin:14px 0;border-left:8px solid #999;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.befund h3{margin:0 0 6px;font-size:16px} .befund p{margin:5px 0;font-size:14px;line-height:1.45} .befund .emp{color:#14532d}
.Hoch{border-color:#d92d20}.Mittel{border-color:#f79009}.Niedrig{border-color:#eab308}.OK{border-color:#12b76a}.Info{border-color:#1f5fae}
.klein{color:#6b7280;font-size:12px} a{color:#1f5fae;text-decoration:none}
.fuss{margin-top:40px;color:#6b7280;font-size:12px;border-top:1px solid #d0d5dd;padding-top:12px}
@media print{body{background:#fff}.befund,.kachel{box-shadow:none;border:1px solid #d0d5dd;border-left-width:8px;break-inside:avoid}}
'@

$h = New-Object System.Text.StringBuilder
[void]$h.Append("<!DOCTYPE html><html lang='$Language'><head><meta charset='utf-8'><title>AD-Schnellcheck $(Html $dom.DNSRoot)</title><style>$css</style></head><body><div class='seite'>")
[void]$h.Append("<h1>AD-Schnellcheck</h1><div class='meta'>$(T 'Domäne' 'Domain') <b>$(Html $dom.DNSRoot)</b> · $(T 'erstellt am' 'created') $($jetzt.ToString((T 'dd.MM.yyyy HH:mm' 'yyyy-MM-dd HH:mm'))) $(T 'von' 'by') $(Html $wer) $(T 'auf' 'on') $(Html $env:COMPUTERNAME)</div>")
[void]$h.Append("<div class='kacheln'>")
foreach ($s in 'Hoch', 'Mittel', 'Niedrig', 'OK') {
    $t = @{ Hoch = (T 'Befunde mit hoher Priorität' 'findings, high priority'); Mittel = (T 'mit mittlerer Priorität' 'medium priority'); Niedrig = (T 'mit niedriger Priorität' 'low priority'); OK = (T 'Prüfpunkte ohne Befund' 'checks without findings') }[$s]
    [void]$h.Append("<div class='kachel $s'><b>$($zahl[$s])</b><span>$t</span></div>")
}
[void]$h.Append("</div>")

[void]$h.Append("<h2>$(T 'Umgebung' 'Environment')</h2><table><tr><th>$(T 'Eigenschaft' 'Property')</th><th>$(T 'Wert' 'Value')</th></tr>")
$fgpp = 0
try { $fgpp = @(Get-ADFineGrainedPasswordPolicy -Filter * @ad).Count } catch { $fgpp = T 'nicht lesbar' 'not readable' }
$umgebung = [ordered]@{
    (T 'Domäne (NetBIOS)' 'Domain (NetBIOS)')                  = "$($dom.DNSRoot) ($($dom.NetBIOSName))"
    (T 'Funktionsebene Domäne / Gesamtstruktur' 'Functional level domain / forest') = "$($dom.DomainMode) / $($wald.ForestMode)"
    (T 'Domänencontroller' 'Domain controllers')                 = (@($dom.ReplicaDirectoryServers) + @($dom.ReadOnlyReplicaDirectoryServers) | Where-Object { $_ }) -join ', '
    (T 'Benutzerkonten (aktiv / gesamt)' 'User accounts (enabled / total)')   = "$($aktive.Count) / $($benutzer.Count)"
    (T 'Privilegierte Konten' 'Privileged accounts')              = $privKonten.Count
    (T 'Gruppen' 'Groups')                           = $gruppen.Count
    (T 'Computerkonten' 'Computer accounts')                    = $computer.Count
    (T 'Kennwortrichtlinie' 'Password policy')                = (T "Länge $($richtlinie.MinPasswordLength), Komplexität $(JaNein $richtlinie.ComplexityEnabled), Chronik $($richtlinie.PasswordHistoryCount), maximales Alter $($richtlinie.MaxPasswordAge.Days) Tage, Sperrschwelle $($richtlinie.LockoutThreshold)" "length $($richtlinie.MinPasswordLength), complexity $(JaNein $richtlinie.ComplexityEnabled), history $($richtlinie.PasswordHistoryCount), maximum age $($richtlinie.MaxPasswordAge.Days) days, lockout threshold $($richtlinie.LockoutThreshold)")
    (T 'Abgestufte Kennwortrichtlinien' 'Fine-grained password policies')    = $fgpp
    (T 'Nicht gelesen' 'Not read')                     = $(if ($privNichtGelesen.Count) { T "Gruppen nicht lesbar: $($privNichtGelesen -join ', ') - A1 und A4 unvollständig" "Groups not readable: $($privNichtGelesen -join ', ') - A1 and A4 incomplete" } else { T 'nichts' 'nothing' })
    (T 'Schwellen dieses Berichts' 'Thresholds of this report')         = (T "auffällig ab mehr als $MaxAdmins Admins" "flagged above $MaxAdmins admins")
}
foreach ($k in $umgebung.Keys) { [void]$h.Append("<tr><td>$(Html $k)</td><td>$(Html $umgebung[$k])</td></tr>") }
[void]$h.Append("</table>")

[void]$h.Append("<h2>$(T 'Übersicht der Prüfpunkte' 'Overview of checks')</h2><table><tr><th>$(T 'Nr.' 'No.')</th><th>$(T 'Bereich' 'Area')</th><th>$(T 'Prüfpunkt' 'Check')</th><th>$(T 'Treffer' 'Hits')</th><th>$(T 'Bewertung' 'Rating')</th></tr>")
foreach ($b in $Befunde) {
    [void]$h.Append("<tr><td>$($b.Id)</td><td>$(Html $b.Bereich)</td><td><a href='#$($b.Id)'>$(Html $b.Titel)</a></td><td>$($b.Anzahl)</td><td><span class='marke m-$($b.Stufe)'>$($stufeText[$b.Stufe])</span></td></tr>")
}
[void]$h.Append("</table>")

[void]$h.Append("<h2>$(T 'Privilegierte Konten' 'Privileged accounts')</h2><p class='klein'>$(T 'Alle Konten, die direkt oder über verschachtelte Gruppen Mitglied einer Administrator- oder Operatorgruppe sind.' 'All accounts that are members of an administrator or operator group, directly or through nested groups.')</p>")
[void]$h.Append((($privKonten | Sort-Object SamAccountName | ForEach-Object { PrivZeile $_ } | ConvertTo-Html -Fragment) -join "`n"))

[void]$h.Append("<h2>$(T 'Befunde' 'Findings')</h2>")
foreach ($b in ($Befunde | Where-Object { $_.Stufe -ne 'OK' } | Sort-Object { $rang[$_.Stufe] }, { [regex]::Replace($_.Id, '\d+', '') }, { [int]('0' + [regex]::Match($_.Id, '\d+').Value) })) {
    [void]$h.Append("<div class='befund $($b.Stufe)' id='$($b.Id)'><h3><span class='marke m-$($b.Stufe)'>$($stufeText[$b.Stufe])</span> $($b.Id) · $(Html $b.Titel) <span class='klein'>($($b.Anzahl) $(T 'Treffer' 'hits'))</span></h3>")
    [void]$h.Append("<p>$(Html $b.Erklaerung)</p><p class='emp'><b>$(T 'Empfehlung' 'Recommendation'):</b> $(Html $b.Empfehlung)</p>")
    if ($b.Anzahl -gt 0) { [void]$h.Append((($b.Objekte | ConvertTo-Html -Fragment) -join "`n")) }
    [void]$h.Append("</div>")
}
$ok = @($Befunde | Where-Object Stufe -eq 'OK')
if ($ok.Count) {
    [void]$h.Append("<h2>$(T 'Ohne Befund' 'No findings')</h2><table><tr><th>$(T 'Nr.' 'No.')</th><th>$(T 'Prüfpunkt' 'Check')</th></tr>")
    foreach ($b in $ok) { [void]$h.Append("<tr id='$($b.Id)'><td>$($b.Id)</td><td>$(Html $b.Titel)</td></tr>") }
    [void]$h.Append("</table>")
}
[void]$h.Append("<div class='hinweis' style='background:#eef4ff;border-left:8px solid #1f5fae;border-radius:10px;padding:14px 18px;margin:30px 0'>$(T '<b>Kostenlose Kurzfassung mit 8 Prüfpunkten.</b> Die Vollversion <b>AD-Prüfbericht</b> prüft 21 Punkte, darunter Dienstkonten mit Administratorrechten, Konten für Kerberoasting, Kennwörter im Beschreibungsfeld, inaktive Konten, das Alter des krbtgt-Kennworts, leere Gruppen und den AD-Papierkorb - mit Anleitung als PDF: ' '<b>Free short edition with 8 checks.</b> The full version <b>AD Audit Report</b> checks 21 points, including service accounts with administrator rights, accounts open to Kerberoasting, passwords in description fields, inactive accounts, the age of the krbtgt password, empty groups and the AD recycle bin - with a PDF guide: ')<a href='https://mueller86.gumroad.com/l/fcneoc'>Gumroad</a> oder <a href='https://www.etsy.com/shop/ITAdminToolsbyMM'>Etsy</a></div>")
[void]$h.Append("<div class='fuss'>AD-Schnellcheck Version $Version · IT Admin Tools by MM · $(T 'Das Skript hat ausschließlich gelesen und nichts verändert. Der Bericht zeigt Auffälligkeiten anhand fester Regeln; er ersetzt keine Sicherheitsprüfung und erhebt keinen Anspruch auf Vollständigkeit. Dieser Bericht enthält Kontonamen - bitte vertraulich behandeln.' 'The script only read and changed nothing. The report shows anomalies based on fixed rules; it is not a substitute for a security audit and makes no claim to completeness. This report contains account names - please treat it as confidential.')</div>")
[void]$h.Append("</div></body></html>")
[System.IO.File]::WriteAllText($Output, $h.ToString(), (New-Object System.Text.UTF8Encoding($true)))

if ($Csv) {
    foreach ($b in ($Befunde | Where-Object { $_.Anzahl -gt 0 })) {
        $b.Objekte | Export-Csv -Path ([System.IO.Path]::ChangeExtension($Output, $null).TrimEnd('.') + "_$($b.Id).csv") -NoTypeInformation -Delimiter ';' -Encoding UTF8
    }
}

Write-Host ''
Write-Host ((T "Fertig: {0} hoch, {1} mittel, {2} niedrig, {3} ohne Befund." "Done: {0} high, {1} medium, {2} low, {3} without findings.") -f $zahl.Hoch, $zahl.Mittel, $zahl.Niedrig, $zahl.OK) -ForegroundColor Green
Write-Host ((T 'Bericht' 'Report') + ": $Output")
if (-not $NoOpen -and [Environment]::UserInteractive) { try { Start-Process $Ausgabe } catch { } }
if ($PassThru) { $Befunde }

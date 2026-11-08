#Requires -Version 5.1
<#
.SYNOPSIS
    AD-Schnellcheck (kostenlose Kurzfassung des AD-Prüfberichts): prüft ein Active Directory in 8 Punkten
    (Kennwortrichtlinie, Administratoren, Benutzerkonten, veraltete Betriebssysteme) und erzeugt einen HTML-Bericht.

    Die Vollversion "AD-Prüfbericht" prüft 21 Punkte (u. a. Dienstkonten mit Adminrechten, Kerberoasting-Ziele,
    Kennwörter im Beschreibungsfeld, inaktive Konten, krbtgt-Alter, leere Gruppen, AD-Papierkorb):
    https://mueller86.gumroad.com/l/fcneoc  oder  https://www.etsy.com/shop/ITAdminToolsbyMM

.DESCRIPTION
    Das Skript arbeitet ausschließlich LESEND. Es ändert nichts im Active Directory, legt nichts an,
    löscht nichts und überträgt keine Daten. Es schreibt genau eine HTML-Datei (und auf Wunsch CSV-Dateien)
    in den angegebenen Ausgabeordner.

    Voraussetzungen: Windows PowerShell 5.1, das Modul "ActiveDirectory" (auf Domänencontrollern vorhanden,
    sonst RSAT "Active Directory Domain Services und Lightweight Directory Services-Tools") und ein
    Domänenkonto mit Leserechten. Administratorrechte sind nicht erforderlich.

.PARAMETER Ausgabe
    Pfad der HTML-Datei. Standard: AD-Schnellcheck_<Domäne>_<Datum>.html im aktuellen Ordner.

.PARAMETER MaxAdmins
    Ab wie vielen privilegierten Konten die Anzahl als auffällig gilt (Standard 5).

.PARAMETER Server
    Bestimmter Domänencontroller oder Domäne (optional).

.PARAMETER Anmeldung
    Anmeldedaten eines Domänenkontos (Get-Credential), falls das Skript nicht als Domänenbenutzer läuft,
    z. B. von einem Rechner außerhalb der Domäne. Dann zusätzlich -Server angeben.

.PARAMETER Csv
    Schreibt zusätzlich je Prüfpunkt mit Treffern eine CSV-Datei neben den Bericht.

.PARAMETER NichtOeffnen
    Öffnet den fertigen Bericht nicht automatisch im Browser.

.PARAMETER PassThru
    Gibt die Befunde zusätzlich als Objekte zurück (für eigene Auswertungen).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\AD-Schnellcheck.ps1

.EXAMPLE
    .\AD-Schnellcheck.ps1 -Csv -Ausgabe C:\Berichte\ad.html

.NOTES
    IT Admin Tools by MM - AD-Schnellcheck Version 1.0 (11.2026), Lizenz: MIT (siehe LICENSE)
    Kein Ersatz für eine Sicherheitsprüfung. Nutzung auf eigene Verantwortung.
#>
[CmdletBinding()]
param(
    [string]$Ausgabe,
    [ValidateRange(1, 1000)][int]$MaxAdmins = 5,
    [string]$Server,
    [System.Management.Automation.PSCredential]$Anmeldung,
    [switch]$Csv,
    [switch]$NichtOeffnen,
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'
$Version = '1.0'

# CSV-Dateien öffnen sich in Excel: Werte, die mit = + - @ beginnen, würden dort als Formel ausgeführt (Namen von Dateien, Ordnern, Konten oder Computern
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
    Write-Host 'Das PowerShell-Modul "ActiveDirectory" fehlt.' -ForegroundColor Red
    Write-Host 'Windows 10/11: Einstellungen > Optionale Features > "RSAT: Active Directory Domain Services" hinzufügen.'
    Write-Host 'Windows Server:  Install-WindowsFeature RSAT-AD-PowerShell'
    exit 2
}
Import-Module ActiveDirectory

$ad = @{}
if ($Server) { $ad.Server = $Server }
if ($Anmeldung) { $ad.Credential = $Anmeldung }

# ------------------------------------------------------------------ Hilfsfunktionen
function Datum($d, $leer = 'nie') { if ($d) { ([datetime]$d).ToString('dd.MM.yyyy') } else { $leer } }
function JaNein($b) { if ($b) { 'Ja' } else { 'Nein' } }
function Ort($dn) { ($dn -replace '^CN=.+?(?<!\\),', '') -replace ',DC=.*$', '' }
function Html($t) { [System.Net.WebUtility]::HtmlEncode([string]$t) }

function BenutzerZeile($u, [hashtable]$Zusatz = @{}) {
    $z = [ordered]@{
        Konto              = $u.SamAccountName
        Name               = $u.Name
        Aktiv              = JaNein $u.Enabled
        'Letzte Anmeldung' = Datum $u.LastLogonDate
        'Kennwort gesetzt' = Datum $u.PasswordLastSet
        Ort                = Ort $u.DistinguishedName
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
Write-Host 'AD-Schnellcheck - es wird nur gelesen, nichts verändert.' -ForegroundColor Cyan
Write-Host '  Domäne und Richtlinien ...'
$dom = Get-ADDomain @ad
$wald = Get-ADForest @ad
$dn = $dom.DistinguishedName
$sid = $dom.DomainSID.Value
$richtlinie = Get-ADDefaultDomainPasswordPolicy @ad
$jetzt = Get-Date

Write-Host '  Benutzerkonten ...'
$eig = 'Enabled', 'PasswordNeverExpires', 'PasswordNotRequired', 'AllowReversiblePasswordEncryption', 'DoesNotRequirePreAuth',
'ServicePrincipalName', 'LastLogonDate', 'PasswordLastSet', 'whenCreated', 'Description', 'MemberOf', 'AccountExpirationDate'
$alle = @(Get-ADUser -Filter * -Properties $eig @ad)
$krbtgt = $alle | Where-Object { $_.SID.Value -eq "$sid-502" }
$gast = $alle | Where-Object { $_.SID.Value -eq "$sid-501" }
# Eingebaute Sonderkonten (Gast, krbtgt, DefaultAccount) werden gesondert bzw. gar nicht bewertet
$benutzer = @($alle | Where-Object { $_.SID.Value -notmatch '-(501|502|503)$' })
$aktive = @($benutzer | Where-Object Enabled)

Write-Host '  Privilegierte Gruppen ...'
$privSids = [ordered]@{
    "$sid-512"     = 'Domänen-Admins'
    "$sid-519"     = 'Organisations-Admins'
    "$sid-518"     = 'Schema-Admins'
    'S-1-5-32-544' = 'Administratoren'
    'S-1-5-32-548' = 'Konten-Operatoren'
    'S-1-5-32-549' = 'Server-Operatoren'
    'S-1-5-32-551' = 'Sicherungs-Operatoren'
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
function PrivZeile($u) { BenutzerZeile $u @{ 'Privilegierte Gruppen' = ($privVon[$u.SamAccountName] -join ', ') } }

Write-Host '  Gruppen und Computer ...'
$gruppen = @(Get-ADGroup -Filter * -Properties member, isCriticalSystemObject, whenCreated @ad)
$computer = @(Get-ADComputer -Filter * -Properties Enabled, OperatingSystem, OperatingSystemVersion, LastLogonDate, whenCreated @ad)

# ------------------------------------------------------------------ Prüfungen
Write-Host '  Auswertung ...'

# --- Kennwortrichtlinie
$r = @()
if ($richtlinie.MinPasswordLength -lt 12) { $r += [pscustomobject]@{ Einstellung = 'Minimale Kennwortlänge'; Ist = "$($richtlinie.MinPasswordLength) Zeichen"; Empfohlen = 'mindestens 12 Zeichen' } }
if (-not $richtlinie.ComplexityEnabled) { $r += [pscustomobject]@{ Einstellung = 'Komplexitätsanforderungen'; Ist = 'deaktiviert'; Empfohlen = 'aktiviert (oder lange Passphrasen erzwingen)' } }
if ($richtlinie.PasswordHistoryCount -lt 10) { $r += [pscustomobject]@{ Einstellung = 'Kennwortchronik'; Ist = "$($richtlinie.PasswordHistoryCount) Kennwörter"; Empfohlen = 'mindestens 10' } }
if ($richtlinie.LockoutThreshold -eq 0) { $r += [pscustomobject]@{ Einstellung = 'Kontosperrungsschwelle'; Ist = 'keine Sperrung'; Empfohlen = 'z. B. 10 Fehlversuche, 15 Minuten' } }
if ($richtlinie.ReversibleEncryptionEnabled) { $r += [pscustomobject]@{ Einstellung = 'Umkehrbare Verschlüsselung'; Ist = 'aktiviert'; Empfohlen = 'deaktiviert' } }
$stufe = 'Mittel'
if ($richtlinie.MinPasswordLength -lt 8 -or $richtlinie.ReversibleEncryptionEnabled) { $stufe = 'Hoch' }
Befund 'R1' 'Kennwortrichtlinie' 'Schwache Einstellungen in der Domänen-Kennwortrichtlinie' $stufe $r `
    'Die Standard-Kennwortrichtlinie der Domäne gilt für alle Konten, für die keine eigene Richtlinie festgelegt ist.' `
    'Einstellungen in der Gruppenrichtlinie "Default Domain Policy" anpassen. Für Administratoren und Dienstkonten bei Bedarf eine strengere abgestufte Kennwortrichtlinie (Fine-Grained Password Policy) anlegen.'

# --- Administratoren
$a = @()
if ($privKonten.Count -gt $MaxAdmins) { $a = $privKonten | Sort-Object SamAccountName | ForEach-Object { PrivZeile $_ } }
Befund 'A1' 'Administratoren' "Mehr als $MaxAdmins privilegierte Konten ($($privKonten.Count))" 'Mittel' $a `
    'Jedes Konto in einer Administratorgruppe ist ein mögliches Einfallstor. Mitgezählt werden auch Konten, die über verschachtelte Gruppen Mitglied sind.' `
    'Liste durchgehen: Wer braucht die Rechte wirklich dauerhaft? Alltagskonten gehören nicht in Administratorgruppen - dafür getrennte Admin-Konten verwenden.'


Befund 'A4' 'Administratoren' 'Privilegierte Konten, deren Kennwort nie abläuft' 'Hoch' `
($privKonten | Where-Object { $_.Enabled -and $_.PasswordNeverExpires } | ForEach-Object { PrivZeile $_ }) `
    'Kennwörter von Administratorkonten, die nie ablaufen, bleiben oft jahrelang unverändert - auch nach Personalwechseln.' `
    'Option "Kennwort läuft nie ab" entfernen. Für das eingebaute Administrator-Konto ein langes Zufallskennwort setzen und sicher hinterlegen (Notfallkonto).'


# Konten und Gruppen, die Exchange bzw. Windows-Rollen selbst anlegen und verwalten (keine Pflege durch den Administrator nötig)
$exchangeSystem = '^(HealthMailbox|SystemMailbox\{|FederatedEmail\.|DiscoverySearchMailbox|Migration\.8f3e7716)'
$exchangeOrte = 'CN=Monitoring Mailboxes,|OU=Microsoft Exchange Security Groups,|CN=Microsoft Exchange System Objects,'

# --- Benutzerkonten
Befund 'K1' 'Benutzerkonten' 'Kennwort läuft nie ab' 'Mittel' `
($aktive | Where-Object { $_.PasswordNeverExpires -and -not $privVon.ContainsKey($_.SamAccountName) -and $_.SamAccountName -notmatch $exchangeSystem -and $_.DistinguishedName -notmatch $exchangeOrte } | ForEach-Object { BenutzerZeile $_ }) `
    'Für diese aktiven Konten ist der Kennwortablauf abgeschaltet (privilegierte Konten stehen unter A4). Konten, die Exchange selbst anlegt und verwaltet (HealthMailbox, SystemMailbox u. ä.), sind ausgenommen.' `
    'Bei Personenkonten die Option entfernen. Bei Dienstkonten ist sie üblich - dann aber ein langes Zufallskennwort verwenden und das Konto dokumentieren.'

Befund 'K2' 'Benutzerkonten' 'Kennwort nicht erforderlich' 'Hoch' `
($aktive | Where-Object PasswordNotRequired | ForEach-Object { BenutzerZeile $_ }) `
    'Diese aktiven Konten dürfen ein leeres Kennwort haben - die Kennwortrichtlinie gilt für sie nicht. Deaktivierte Konten (z. B. Systemkonten von Exchange) sind ausgenommen.' `
    'Option entfernen: Set-ADUser <Konto> -PasswordNotRequired $false, danach Kennwort neu setzen.'


Befund 'K4' 'Benutzerkonten' 'Kerberos-Vorauthentifizierung abgeschaltet' 'Hoch' `
($benutzer | Where-Object DoesNotRequirePreAuth | ForEach-Object { BenutzerZeile $_ }) `
    'Für diese Konten kann jeder im Netz ohne Anmeldung Daten abrufen, mit denen sich das Kennwort offline erraten lässt (AS-REP-Roasting).' `
    'Option "Keine Kerberos-Vorauthentifizierung erforderlich" entfernen.'


$g = @()
if ($gast -and $gast.Enabled) { $g = BenutzerZeile $gast }
Befund 'K10' 'Benutzerkonten' 'Gastkonto ist aktiviert' 'Hoch' $g `
    'Über das Gastkonto ist eine Anmeldung ohne persönliches Konto möglich.' 'Gastkonto deaktivieren.'


# --- Computer
# Windows 10 (ohne LTSC/IoT, deren Support länger läuft) ist seit dem 14.10.2025 ohne Sicherheitsupdates, außer mit bezahlten Erweiterten Sicherheitsupdates (ESU)
$altMuster = 'Windows (XP|Vista|7|8|8\.1)( |$)|Windows 10(?!.*(LTS[CB]|IoT))|Windows 2000|Windows NT|Server.? (2000|2003|2008|2012)'
Befund 'C1' 'Computer' 'Computer mit nicht mehr unterstütztem Betriebssystem' 'Hoch' `
($computer | Where-Object { $_.Enabled -and $_.OperatingSystem -match $altMuster } | Sort-Object Name |
    ForEach-Object { [pscustomobject]@{ Computer = $_.Name; Betriebssystem = $_.OperatingSystem; 'Letzte Anmeldung' = Datum $_.LastLogonDate; Ort = Ort $_.DistinguishedName } }) `
    'Für diese Systeme gibt es keine Sicherheitsupdates mehr (Windows 10 nur noch mit kostenpflichtigen Erweiterten Sicherheitsupdates). Grundlage ist der im Verzeichnis eingetragene Betriebssystemname.' `
    'Systeme ablösen oder vom Netz trennen. Wenn das Gerät nicht mehr existiert: Computerkonto löschen.'


# ------------------------------------------------------------------ Bericht
Write-Host '  Bericht schreiben ...'
if (-not $Ausgabe) { $Ausgabe = Join-Path (Get-Location).Path ("AD-Schnellcheck_{0}_{1:yyyy-MM-dd_HHmm}.html" -f $dom.DNSRoot, $jetzt) }
$Ausgabe = [System.IO.Path]::GetFullPath($Ausgabe)
$ordner = Split-Path $Ausgabe -Parent
if (-not (Test-Path $ordner)) { New-Item -ItemType Directory -Path $ordner -Force | Out-Null }

$rang = @{ Hoch = 0; Mittel = 1; Niedrig = 2; Info = 3; OK = 4 }
$zahl = @{}
foreach ($s in 'Hoch', 'Mittel', 'Niedrig', 'OK') { $zahl[$s] = @($Befunde | Where-Object Stufe -eq $s).Count }

$wer = "$env:USERDOMAIN\$env:USERNAME"
if ($Anmeldung) { $wer = $Anmeldung.UserName }

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
[void]$h.Append("<!DOCTYPE html><html lang='de'><head><meta charset='utf-8'><title>AD-Schnellcheck $(Html $dom.DNSRoot)</title><style>$css</style></head><body><div class='seite'>")
[void]$h.Append("<h1>AD-Schnellcheck</h1><div class='meta'>Domäne <b>$(Html $dom.DNSRoot)</b> · erstellt am $($jetzt.ToString('dd.MM.yyyy HH:mm')) von $(Html $wer) auf $(Html $env:COMPUTERNAME)</div>")
[void]$h.Append("<div class='kacheln'>")
foreach ($s in 'Hoch', 'Mittel', 'Niedrig', 'OK') {
    $t = @{ Hoch = 'Befunde mit hoher Priorität'; Mittel = 'mit mittlerer Priorität'; Niedrig = 'mit niedriger Priorität'; OK = 'Prüfpunkte ohne Befund' }[$s]
    [void]$h.Append("<div class='kachel $s'><b>$($zahl[$s])</b><span>$t</span></div>")
}
[void]$h.Append("</div>")

[void]$h.Append("<h2>Umgebung</h2><table><tr><th>Eigenschaft</th><th>Wert</th></tr>")
$fgpp = 0
try { $fgpp = @(Get-ADFineGrainedPasswordPolicy -Filter * @ad).Count } catch { $fgpp = 'nicht lesbar' }
$umgebung = [ordered]@{
    'Domäne (NetBIOS)'                  = "$($dom.DNSRoot) ($($dom.NetBIOSName))"
    'Funktionsebene Domäne / Gesamtstruktur' = "$($dom.DomainMode) / $($wald.ForestMode)"
    'Domänencontroller'                 = (@($dom.ReplicaDirectoryServers) + @($dom.ReadOnlyReplicaDirectoryServers) | Where-Object { $_ }) -join ', '
    'Benutzerkonten (aktiv / gesamt)'   = "$($aktive.Count) / $($benutzer.Count)"
    'Privilegierte Konten'              = $privKonten.Count
    'Gruppen'                           = $gruppen.Count
    'Computerkonten'                    = $computer.Count
    'Kennwortrichtlinie'                = "Länge $($richtlinie.MinPasswordLength), Komplexität $(JaNein $richtlinie.ComplexityEnabled), Chronik $($richtlinie.PasswordHistoryCount), maximales Alter $($richtlinie.MaxPasswordAge.Days) Tage, Sperrschwelle $($richtlinie.LockoutThreshold)"
    'Abgestufte Kennwortrichtlinien'    = $fgpp
    'Nicht gelesen'                     = $(if ($privNichtGelesen.Count) { "Gruppen nicht lesbar: $($privNichtGelesen -join ', ') - A1 und A4 unvollständig" } else { 'nichts' })
    'Schwellen dieses Berichts'         = "auffällig ab mehr als $MaxAdmins Admins"
}
foreach ($k in $umgebung.Keys) { [void]$h.Append("<tr><td>$(Html $k)</td><td>$(Html $umgebung[$k])</td></tr>") }
[void]$h.Append("</table>")

[void]$h.Append("<h2>Übersicht der Prüfpunkte</h2><table><tr><th>Nr.</th><th>Bereich</th><th>Prüfpunkt</th><th>Treffer</th><th>Bewertung</th></tr>")
foreach ($b in $Befunde) {
    [void]$h.Append("<tr><td>$($b.Id)</td><td>$(Html $b.Bereich)</td><td><a href='#$($b.Id)'>$(Html $b.Titel)</a></td><td>$($b.Anzahl)</td><td><span class='marke m-$($b.Stufe)'>$($b.Stufe)</span></td></tr>")
}
[void]$h.Append("</table>")

[void]$h.Append("<h2>Privilegierte Konten</h2><p class='klein'>Alle Konten, die direkt oder über verschachtelte Gruppen Mitglied einer Administrator- oder Operatorgruppe sind.</p>")
[void]$h.Append((($privKonten | Sort-Object SamAccountName | ForEach-Object { PrivZeile $_ } | ConvertTo-Html -Fragment) -join "`n"))

[void]$h.Append("<h2>Befunde</h2>")
foreach ($b in ($Befunde | Where-Object { $_.Stufe -ne 'OK' } | Sort-Object { $rang[$_.Stufe] }, { [regex]::Replace($_.Id, '\d+', '') }, { [int]('0' + [regex]::Match($_.Id, '\d+').Value) })) {
    [void]$h.Append("<div class='befund $($b.Stufe)' id='$($b.Id)'><h3><span class='marke m-$($b.Stufe)'>$($b.Stufe)</span> $($b.Id) · $(Html $b.Titel) <span class='klein'>($($b.Anzahl) Treffer)</span></h3>")
    [void]$h.Append("<p>$(Html $b.Erklaerung)</p><p class='emp'><b>Empfehlung:</b> $(Html $b.Empfehlung)</p>")
    if ($b.Anzahl -gt 0) { [void]$h.Append((($b.Objekte | ConvertTo-Html -Fragment) -join "`n")) }
    [void]$h.Append("</div>")
}
$ok = @($Befunde | Where-Object Stufe -eq 'OK')
if ($ok.Count) {
    [void]$h.Append("<h2>Ohne Befund</h2><table><tr><th>Nr.</th><th>Prüfpunkt</th></tr>")
    foreach ($b in $ok) { [void]$h.Append("<tr id='$($b.Id)'><td>$($b.Id)</td><td>$(Html $b.Titel)</td></tr>") }
    [void]$h.Append("</table>")
}
[void]$h.Append("<div class='hinweis' style='background:#eef4ff;border-left:8px solid #1f5fae;border-radius:10px;padding:14px 18px;margin:30px 0'><b>Kostenlose Kurzfassung mit 8 Prüfpunkten.</b> Die Vollversion <b>AD-Prüfbericht</b> prüft 21 Punkte, darunter Dienstkonten mit Administratorrechten, Konten für Kerberoasting, Kennwörter im Beschreibungsfeld, inaktive Konten, das Alter des krbtgt-Kennworts, leere Gruppen und den AD-Papierkorb - mit Anleitung als PDF: <a href='https://mueller86.gumroad.com/l/fcneoc'>Gumroad</a> oder <a href='https://www.etsy.com/shop/ITAdminToolsbyMM'>Etsy</a></div>")
[void]$h.Append("<div class='fuss'>AD-Schnellcheck Version $Version · IT Admin Tools by MM · Das Skript hat ausschließlich gelesen und nichts verändert. Der Bericht zeigt Auffälligkeiten anhand fester Regeln; er ersetzt keine Sicherheitsprüfung und erhebt keinen Anspruch auf Vollständigkeit. Dieser Bericht enthält Kontonamen - bitte vertraulich behandeln.</div>")
[void]$h.Append("</div></body></html>")
[System.IO.File]::WriteAllText($Ausgabe, $h.ToString(), (New-Object System.Text.UTF8Encoding($true)))

if ($Csv) {
    foreach ($b in ($Befunde | Where-Object { $_.Anzahl -gt 0 })) {
        $b.Objekte | Export-Csv -Path ([System.IO.Path]::ChangeExtension($Ausgabe, $null).TrimEnd('.') + "_$($b.Id).csv") -NoTypeInformation -Delimiter ';' -Encoding UTF8
    }
}

Write-Host ''
Write-Host ("Fertig: {0} hoch, {1} mittel, {2} niedrig, {3} ohne Befund." -f $zahl.Hoch, $zahl.Mittel, $zahl.Niedrig, $zahl.OK) -ForegroundColor Green
Write-Host "Bericht: $Ausgabe"
if (-not $NichtOeffnen -and [Environment]::UserInteractive) { try { Start-Process $Ausgabe } catch { } }
if ($PassThru) { $Befunde }

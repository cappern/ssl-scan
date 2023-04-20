param (
    [string]$subnet = "",
    [string]$ipAddress = "",
    [string]$outputFile = "ssl-certificates.csv"
)

# Angi listen over porter du vil sjekke
$ports = @("443","8443","1880")

# Funksjon for å sjekke om en port er åpen på en enhet
function Check-Port($ipAddress, $port)
{
    $socket = New-Object Net.Sockets.TcpClient
    $asyncResult = $socket.BeginConnect($ipAddress, $port, $null, $null)
    $waitHandle = $asyncResult.AsyncWaitHandle
    try
    {
        if ($waitHandle.WaitOne(1000, $false))
        {
            $socket.EndConnect($asyncResult) | Out-Null
            return $true
        }
        else
        {
            return $false
        }
    }
    catch
    {
        return $false
    }
    finally
    {
        $socket.Dispose()
        $waitHandle.Dispose()
    }
}

# Funksjon for å hente SSL-sertifikatet fra en enhet
function Get-SSLInfo($ipAddress, $port)
{
    $tcpClient = New-Object System.Net.Sockets.TcpClient
    try
    {
        $tcpClient.Connect($ipAddress, $port)
        $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false, { param($sender, $cert, $chain, $sslPolicyErrors) $true })
        $sslStream.AuthenticateAsClient($ipAddress)
        $cert = $sslStream.RemoteCertificate
        if($cert -ne $null)
        {
            $subject = $cert.Subject
            $issuer = $cert.Issuer
            $validFrom = $cert.GetEffectiveDateString()
            $validTo = $cert.GetExpirationDateString()
            return $subject + "," + $issuer + "," + $validFrom + "," + $validTo
        }
    }
    catch
    {
        return $null
    }
    finally
    {
        $tcpClient.Dispose()
    }
}

# Skanne en enkelt IP-adresse
function Scan-IPAddress($ipAddress, $ports)
{
    $results = @()
    foreach ($port in $ports)
    {
        if (Check-Port $ipAddress $port)
        {
            $sslInfo = Get-SSLInfo $ipAddress $port
            $result = New-Object PSObject
            $result | Add-Member -MemberType NoteProperty -Name "IP Address" -Value $ipAddress
            $result | Add-Member -MemberType NoteProperty -Name "Port" -Value $port
            $result | Add-Member -MemberType NoteProperty -Name "SSL Certificate" -Value $sslInfo
            $results += $result
        }
    }
    return $results
}

# Skanne subnettet
function Scan-Subnet($subnet, $ports)
{
    $results = @()
    for ($i = 1; $i -le 255; $i++)
    {
        $ipAddress = $subnet + "." + $i
        $ipResults = Scan-IPAddress $ipAddress $ports
        $results += $ipResults
    }
    return $results
}

# Hovedprogram
if ($ipAddress
{
# Skanne enkelt IP-adresse
$results = Scan-IPAddress $ipAddress $ports
}
else
{
# Skanne subnettet
$results = Scan-Subnet $subnet $ports
}

Lagre resultatene til CSV-filen

$results | Export-Csv $outputFile -NoTypeInformation

# Auth0 Token Fetch Script
# Usage: .\scripts\getToken.ps1 -ClientId "your_client_id" -ClientSecret "your_client_secret"
param(
  [string]$ClientId = "PIAvI4kXAiP5f2Twn3Qf0qufp0bPOHim",
  [string]$ClientSecret = "qz56WcSudCrWJyPJSIYzuxl8MIt5fIpxJlpW_Z5x31Z2kUxPUzpFerVbmcVZjrR5"
)
$body = @{
  client_id     = $ClientId
  client_secret = $ClientSecret
  audience      = "https://auth-service.example.com"
  grant_type    = "client_credentials"
} | ConvertTo-Json

Write-Host "Requesting token from Auth0..." -ForegroundColor Cyan

try {
  $tokenResponse = Invoke-RestMethod `
    -Uri "https://dev-gx56u528ljl5u6mo.us.auth0.com/oauth/token" `
    -Method Post `
    -ContentType "application/json" `
    -Body $body

  $token = $tokenResponse.access_token
  Write-Host "Token generated successfully!" -ForegroundColor Green
  $masked = $token.Substring(0, 15) + "..." + $token.Substring($token.Length - 10)
  Write-Host "Access Token (masked): $masked" -ForegroundColor Yellow

  # Set to clipboard for easy pasting
  Set-Clipboard -Value $token
  Write-Host "(Token has also been copied to your clipboard!)" -ForegroundColor Gray
} catch {
  Write-Host "Error fetching token: $_" -ForegroundColor Red
}

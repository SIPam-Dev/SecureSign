@echo off
setlocal

SET "PUBLISHED_BASE=%~dp0"

del /s /q "%PUBLISHED_BASE%published"
dotnet publish -c Release -o "%PUBLISHED_BASE%published" src/SecureSign.Web/
dotnet publish -c Release -o "%PUBLISHED_BASE%published" src/SecureSign.Tools/

endlocal
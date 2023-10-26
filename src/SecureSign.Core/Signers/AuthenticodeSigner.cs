/**
 * Copyright (c) 2017 Daniel Lo Nigro (Daniel15)
 * 
 * This source code is licensed under the MIT license found in the 
 * LICENSE file in the root directory of this source tree. 
 */

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using SecureSign.Core.Exceptions;
using SecureSign.Core.Extensions;
using SecureSign.Core.Models;

namespace SecureSign.Core.Signers
{
	/// <summary>
	/// A signer implementation that signs files with an Authenticode signature.
	/// </summary>
	public class AuthenticodeSigner : IAuthenticodeSigner, IDisposable
	{
		private const int TIMEOUT = 60_000;

		private readonly IPasswordGenerator _passwordGenerator;
		private readonly PathConfig _pathConfig;
		/// <summary>
		/// Files to delete AFTER the request completes.
		/// </summary>
		private readonly List<string> _filesToDelete = new List<string>();

		/// <summary>
		/// Creates a new <see cref="AuthenticodeSigner"/>.
		/// </summary>
		/// <param name="passwordGenerator"></param>
		public AuthenticodeSigner(IPasswordGenerator passwordGenerator, IOptions<PathConfig> pathConfig)
		{
			_passwordGenerator = passwordGenerator;
			_pathConfig = pathConfig.Value;
		}

		/// <summary>
		/// Signs the provided resource with an Authenticode signature.
		/// </summary>
		/// <param name="input">Object to sign</param>
		/// <param name="configData">Configuration data for signing</param>
		/// <param name="configKey">Configuration key, e.g. to decrypt/access configuration data</param>
		/// <param name="cert">Certificate to use for signing</param>
		/// <param name="description">Description to sign the object with</param>
		/// <param name="url">URL to include in the signature</param>
		/// <returns>A signed copy of the file</returns>
		public async Task<Stream> SignAsync(Stream input, byte[] configData, string configKey, string description, string url, string fileExtention)
		{
			if (X509Certificate2.GetCertContentType(configData) != X509ContentType.Unknown)
			{
				var cert = new X509Certificate2(configData, configKey, X509KeyStorageFlags.Exportable);
				return await SignAsync(input, cert, description, url, fileExtention);
			}

			using (var stream = new MemoryStream(configData, false))
			using (var reader = new StreamReader(stream, true))
			{
				var config = JsonConvert.DeserializeObject<AzureSignToolConfig>(reader.ReadToEnd());
				var inputFile = Path.GetTempFileName() + fileExtention;
				_filesToDelete.Add(inputFile);

				await input.CopyToFileAsync(inputFile);
				return await SignUsingAzureSignToolAsync(inputFile, config.KeyVaultUrl, config.KeyVaultTenant, config.KeyVaultClient, config.KeyVaultClientSecret, config.KeyVaultCert, description, url);
			}
		}

		/// <summary>
		/// Signs the provided resource with an Authenticode signature.
		/// </summary>
		/// <param name="input">Object to sign</param>
		/// <param name="cert">Certificate to use for signing</param>
		/// <param name="description">Description to sign the object with</param>
		/// <param name="url">URL to include in the signature</param>
		/// <returns>A signed copy of the file</returns>
		private async Task<Stream> SignAsync(Stream input, X509Certificate2 cert, string description, string url, string fileExtention)
		{
			// Temporarily save the cert to disk with a random password, as osslsigncode needs to read it from disk.
			var password = _passwordGenerator.Generate();
			var inputFile = Path.GetTempFileName() + fileExtention;
			var certFile = Path.GetTempFileName();
			_filesToDelete.Add(inputFile);

			try
			{
				var exportedCert = cert.Export(X509ContentType.Pfx, password);
				File.WriteAllBytes(certFile, exportedCert);
				await input.CopyToFileAsync(inputFile);

				if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
				{
					if (fileExtention.Contains("ps"))
					{
						return await SignUsingPowerShellAsync(inputFile, certFile, password);
					}
					else
					{
						return await SignUsingSignToolAsync(inputFile, certFile, password, description, url);
					}
				}
				else
				{
					return await SignUsingOpenSsl(inputFile, certFile, password, description, url);
				}

			}
			finally
			{
				File.Delete(certFile);
			}
		}

		/// <summary>
		/// Signs the specified file using signtool.exe from the Windows SDK
		/// </summary>
		/// <param name="inputFile">File to sign</param>
		/// <param name="certFile">Path to the certificate to use for signing</param>
		/// <param name="certPassword">Password for the certificate</param>
		/// <param name="description">Description to sign the object with</param>
		/// <param name="url">URL to include in the signature</param>
		/// <returns>A signed copy of the file</returns>
		private async Task<Stream> SignUsingSignToolAsync(string inputFile, string certFile, string certPassword, string description, string url)
		{
			// dual sign using sha1 ...
			await RunProcessAsync(
				_pathConfig.SignTool,
				new[]
				{
					"sign",
					"/v",
					$"/f \"{CommandLineEncoder.Utils.EncodeArgText(certFile)}\"",
					$"/p \"{CommandLineEncoder.Utils.EncodeArgText(certPassword)}\"",
					$"/d \"{CommandLineEncoder.Utils.EncodeArgText(description)}\"",
					$"/du \"{CommandLineEncoder.Utils.EncodeArgText(url)}\"",
					"/t http://timestamp.digicert.com",
					"/fd sha1",
					$"\"{CommandLineEncoder.Utils.EncodeArgText(inputFile)}\"",
				}
			);
			// and sha256 ...
			await RunProcessAsync(
				_pathConfig.SignTool,
				new[]
				{
					"sign",
					"/v",
					$"/f \"{CommandLineEncoder.Utils.EncodeArgText(certFile)}\"",
					$"/p \"{CommandLineEncoder.Utils.EncodeArgText(certPassword)}\"",
					$"/d \"{CommandLineEncoder.Utils.EncodeArgText(description)}\"",
					$"/du \"{CommandLineEncoder.Utils.EncodeArgText(url)}\"",
					//"/tr http://timestamp.globalsign.com/scripts/timestamp.dll",
					"/tr http://timestamp.digicert.com?td=sha256",
					"/td sha256",
					"/fd sha256",
					"/as",
					$"\"{CommandLineEncoder.Utils.EncodeArgText(inputFile)}\"",
				}
			);

			// SignTool signs in-place, so just return the file we were given.
			return File.OpenRead(inputFile);
		}

		/// <summary>
		/// Signs the specified file using azureSignTool.exe from Kevin Jones (https://github.com/vcsjones/AzureSignTool)
		/// </summary>
		/// <param name="inputFile">File to sign</param>
		/// <param name="keyVaultUrl">URL of the Azure KeyVault</param>
		/// <param name="keyVaultTenant">ID of the Azure Tenant</param>
		/// <param name="keyVaultClient">ID of the Azure Client (Application ID)</param>
		/// <param name="keyVaultClientSecret">Azure client secret</param>
		/// <param name="certName">Name of the certificate in KeyVault</param>
		/// <param name="description">Description to sign the object with</param>
		/// <param name="url">URL to include in the signature</param>
		/// <returns>A signed copy of the file</returns>
		private async Task<Stream> SignUsingAzureSignToolAsync(string inputFile, string keyVaultUrl, string keyVaultTenant, string keyVaultClient, string keyVaultClientSecret, string certName, string description, string url)
		{
			// dual sign using sha1 ...
			// dual signing is not possible due to api limitations
			/*
			await RunProcessAsync(
				_pathConfig.AzureSignTool,
				new[]
				{
					"AzureSignTool",
					"-v",
					$"-kvu \"{CommandLineEncoder.Utils.EncodeArgText(keyVaultUrl)}\"",
					$"-kvt \"{CommandLineEncoder.Utils.EncodeArgText(keyVaultTenant)}\"",
					$"-kvc \"{CommandLineEncoder.Utils.EncodeArgText(certName)}\"",
					$"-kvi \"{CommandLineEncoder.Utils.EncodeArgText(keyVaultClient)}\"",
					$"-kvs \"{CommandLineEncoder.Utils.EncodeArgText(keyVaultClientSecret)}\"",
					$"-d \"{CommandLineEncoder.Utils.EncodeArgText(description)}\"",
					$"-du \"{CommandLineEncoder.Utils.EncodeArgText(url)}\"",
					"-td sha1", "-tr http://timestamp.digicert.com?td=sha1",
					"-fd sha1",
					// "-ph", // activate page hashing?
					$"\"{CommandLineEncoder.Utils.EncodeArgText(inputFile)}\"",
				}
			);
			*/
			// and sha256 ...
			await RunProcessAsync(
				_pathConfig.AzureSignTool,
				new[]
				{
					"AzureSignTool",
					"-v",
					$"-kvu \"{CommandLineEncoder.Utils.EncodeArgText(keyVaultUrl)}\"",
					$"-kvt \"{CommandLineEncoder.Utils.EncodeArgText(keyVaultTenant)}\"",
					$"-kvc \"{CommandLineEncoder.Utils.EncodeArgText(certName)}\"",
					$"-kvi \"{CommandLineEncoder.Utils.EncodeArgText(keyVaultClient)}\"",
					$"-kvs \"{CommandLineEncoder.Utils.EncodeArgText(keyVaultClientSecret)}\"",
					$"-d \"{CommandLineEncoder.Utils.EncodeArgText(description)}\"",
					$"-du \"{CommandLineEncoder.Utils.EncodeArgText(url)}\"",
					"-td sha256", "-tr http://timestamp.digicert.com?td=sha256",
					"-fd sha256",
					// "-ph", // activate page hashing?
					$"\"{CommandLineEncoder.Utils.EncodeArgText(inputFile)}\"",
				}
			);

			// AzureSignTool signs in-place, so just return the file we were given.
			return File.OpenRead(inputFile);
		}

		/// <summary>
		/// Signs the specified file using Powershell Set-Authenticode
		/// </summary>
		/// <param name="inputFile">File to sign</param>
		/// <param name="certFile">Path to the certificate to use for signing</param>
		/// <param name="certPassword">Password for the certificate</param>
		/// <returns>A signed copy of the file</returns>
		private async Task<Stream> SignUsingPowerShellAsync(string inputFile, string certFile, string certPassword)
		{
			await RunProcessAsync(
				"powershell.exe",
				new[]
				{
					"-command",
					"\"$Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2;",
					$"$Cert.Import('{CommandLineEncoder.Utils.EncodeArgText(certFile)}','{CommandLineEncoder.Utils.EncodeArgText(certPassword)}',[System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet);",
					$"Set-AuthenticodeSignature '{CommandLineEncoder.Utils.EncodeArgText(inputFile)}' $Cert -Timestamp http://timestamp.digicert.com\"",
				}
			);

			// PowerShell signs in-place, so just return the file we were given.
			return File.OpenRead(inputFile);
		}

		/// <summary>
		/// Signs the specified file using osslsigncode
		/// </summary>
		/// <param name="inputFile">File to sign</param>
		/// <param name="certFile">Path to the certificate to use for signing</param>
		/// <param name="certPassword">Password for the certificate</param>
		/// <param name="description">Description to sign the object with</param>
		/// <param name="url">URL to include in the signature</param>
		/// <returns>A signed copy of the file</returns>
		private async Task<Stream> SignUsingOpenSsl(string inputFile, string certFile, string certPassword,
			string description, string url)
		{
			// An intermediate file is used for dual signing since osslsigncode no longer supports in-place signing.
			var intermediateFile = Path.GetTempFileName();
			var outputFile = Path.GetTempFileName();
			_filesToDelete.Add(intermediateFile);
			_filesToDelete.Add(outputFile);

			// Path.GetTempFileName() creates the file on disk, which osslsigncode doesn't like, so delete them first.
			File.Delete(intermediateFile);
			File.Delete(outputFile);

			// Command-line arguments can be shown in the output of "ps". Therefore, we don't want to pass
			// the certificate's password at the command-line. Instead, save it into a temp file that's
			// deleted once the signing has been completed
			var certPasswordFile = Path.GetTempFileName();

			try
			{
				File.WriteAllText(certPasswordFile, certPassword);

				// Windows 7 and 10 have deprecated SHA1 and require SHA256 or higher,
				// however Vista and XP don't support SHA256. To fix this, we sign using
				// *both* methods (dual signing).
				// Reference: http://www.elstensoftware.com/blog/2016/02/10/dual-signing-osslsigncode/

				// First sign with SHA1
				await RunOsslSignCodeAsync(certFile, certPasswordFile, description, url, new[]
				{
					"-h sha1",
					$"-in \"{CommandLineEncoder.Utils.EncodeArgText(inputFile)}\"",
					$"-out \"{CommandLineEncoder.Utils.EncodeArgText(intermediateFile)}\"",
				});

				// Now sign with SHA256
				await RunOsslSignCodeAsync(certFile, certPasswordFile, description, url, new[]
				{
					"-nest",
					"-h sha2",
					$"-in \"{CommandLineEncoder.Utils.EncodeArgText(intermediateFile)}\"",
					$"-out \"{CommandLineEncoder.Utils.EncodeArgText(outputFile)}\"",
				});

				return File.OpenRead(outputFile);
			}
			finally
			{
				File.Delete(certPasswordFile);
			}
		}

		private async Task RunOsslSignCodeAsync(string certFile, string certPasswordFile, string description, string url, string[] extraArgs)
		{
			var args = new List<string>
			{
				"sign",
				"-ts http://timestamp.digicert.com",
				$"-n \"{CommandLineEncoder.Utils.EncodeArgText(description)}\"",
				$"-i \"{CommandLineEncoder.Utils.EncodeArgText(url)}\"",
				$"-pkcs12 \"{CommandLineEncoder.Utils.EncodeArgText(certFile)}\"",
				$"-readpass \"{CommandLineEncoder.Utils.EncodeArgText(certPasswordFile)}\""
			};
			await RunProcessAsync("osslsigncode", args.Concat(extraArgs).ToArray());
		}

		/// <summary>
		/// Runs an external process and waits it to return.
		/// </summary>
		/// <param name="appName">Executeable to run</param>
		/// <param name="args">Arguments to pass</param>
		/// <exception cref="AuthenticodeFailedException">If a non-zero error code is returned</exception>
		private async Task RunProcessAsync(string appName, params string[] args)
		{
			var process = new Process
			{
				StartInfo =
				{
					FileName = appName,
					Arguments = string.Join(" ", args),
					CreateNoWindow = true,
					RedirectStandardError = true,
					RedirectStandardOutput = true,
					UseShellExecute = false,
				}
			};
			process.Start();
			process.WaitForExit(TIMEOUT);

			if (process.ExitCode != 0)
			{
				var errorOutput = await process.StandardError.ReadToEndAsync();
				var stdOutput = await process.StandardOutput.ReadToEndAsync();
				throw new AuthenticodeFailedException("Failed to Authenticode sign: " + process.ExitCode.ToString() + "\n" + errorOutput + ", " + stdOutput);
			}
		}

		public void Dispose()
		{
			foreach (var file in _filesToDelete)
			{
				File.Delete(file);
			}
		}
	}
}

using System;
using System.IO;
using System.Text;
using Newtonsoft.Json;
using SecureSign.Core;
using SecureSign.Core.Extensions;
using SecureSign.Core.Models;

namespace SecureSign.Tools.KeyHandlers
{
	/// <summary>
	/// Handles storing and creating access tokens for Authenticode keys
	/// </summary>
	class AzureKeyVaultKeyHandler: IKeyHandler
	{
		private readonly IPasswordGenerator _passwordGenerator;
		private readonly ISecretStorage _secretStorage;

		public AzureKeyVaultKeyHandler(IPasswordGenerator passwordGenerator, ISecretStorage secretStorage)
		{
			_passwordGenerator = passwordGenerator;
			_secretStorage = secretStorage;
		}

		/// <summary>
		/// Gets the key type that this key handler supports
		/// </summary>
		public KeyType KeyType => KeyType.AzureKeyVault;

		/// <summary>
		/// Adds a new key to the secret storage.
		/// </summary>
		/// <param name="inputPath"></param>
		public void AddKey(string inputPath)
		{
			// Ensure output file does not exist
			var fileName = Path.GetFileName(inputPath);
			_secretStorage.ThrowIfSecretExists(fileName);

			var password = ConsoleUtils.PasswordPrompt("Password");
			var inputData = File.ReadAllBytes(inputPath);

			using (var stream = new MemoryStream(inputData, false))
			using (var reader = new StreamReader(stream, true))
			{
				var config = JsonConvert.DeserializeObject<AzureSignToolConfig>(reader.ReadToEnd());
				config.KeyVaultClientSecret = password.ToAnsiString();
				var code = _passwordGenerator.Generate();

				_secretStorage.SaveSecret(fileName, Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(config)), code);
				Console.WriteLine();
				Console.WriteLine($"Saved {fileName}");
				Console.WriteLine($"Certificate name: {config.KeyVaultCert}");
				Console.WriteLine($"Tenant id: {config.KeyVaultTenant}");
				Console.WriteLine($"Client id: {config.KeyVaultClient}");
				Console.WriteLine();
				Console.WriteLine($"Secret Code: {code}");
			}
		}

		/// <summary>
		/// Creates a new access token to use the specified key
		/// </summary>
		/// <param name="code">Encryption code for the key</param>
		/// <param name="name">Name of the key</param>
		/// <returns>Access token and its config</returns>
		public (AccessToken accessToken, AccessTokenConfig accessTokenConfig) CreateAccessToken(
			string code,
			string name
		)
		{
			var comment = ConsoleUtils.Prompt("Comment (optional)");

			Console.WriteLine();
			Console.WriteLine("Signing settings:");
			var desc = ConsoleUtils.Prompt("Description");
			var url = ConsoleUtils.Prompt("Product/Application URL");

			var accessToken = new AccessToken
			{
				Id = Guid.NewGuid().ToShortGuid(),
				Code = code,
				IssuedAt = DateTime.Now,
				KeyName = name,
			};
			var accessTokenConfig = new AccessTokenConfig
			{
				Comment = comment,
				IssuedAt = accessToken.IssuedAt,
				Valid = true,

				SignDescription = desc,
				SignUrl = url,
			};
			return (accessToken, accessTokenConfig);
		}
	}
}

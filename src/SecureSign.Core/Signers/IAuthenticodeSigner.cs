/**
 * Copyright (c) 2017 Daniel Lo Nigro (Daniel15)
 * 
 * This source code is licensed under the MIT license found in the 
 * LICENSE file in the root directory of this source tree. 
 */

using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using SecureSign.Core.Models;

namespace SecureSign.Core.Signers
{
	/// <summary>
	/// A signer implementation that signs files with an Authenticode signature.
	/// </summary>
	public interface IAuthenticodeSigner
	{
		/// <summary>
		/// Signs the provided resource with an Authenticode signature.
		/// </summary>
		/// <param name="input">Object to sign</param>
		/// <param name="configData">Configuration data for signing</param>
		/// <param name="token">Access token, e.g. to decrypt/access configuration data</param>
		/// <param name="description">Description to sign the object with</param>
		/// <param name="url">URL to include in the signature</param>
		/// <param name="fileExtention">Extention type of the file to sign</param>
		/// <returns>A signed copy of the file</returns>
		Task<Stream> SignAsync(Stream input, byte[] configData, AccessToken token, string description, string url, string fileExtention);
	}
}
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security;

namespace SecureSign.Core.Models
{
	public class AzureSignToolConfig
	{
		/// <summary>
		/// Key vault URL
		/// </summary>
		public string KeyVaultUrl { get; set; } = string.Empty;
		/// <summary>
		/// Key vault tenant id
		/// </summary>
		public string KeyVaultTenant { get; set; } = string.Empty;
		/// <summary>
		/// Key vault client id (application id)
		/// </summary>
		public string KeyVaultClient { get; set; } = string.Empty;
		/// <summary>
		/// Key vault client secret
		/// </summary>
		public string KeyVaultClientSecret { get; set; } = string.Empty;
		/// <summary>
		/// Key vault certificate name
		/// </summary>
		public string KeyVaultCert { get; set; } = string.Empty;
	}
}

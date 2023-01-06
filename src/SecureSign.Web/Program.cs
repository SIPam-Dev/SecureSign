/**
 * Copyright (c) 2017 Daniel Lo Nigro (Daniel15)
 * 
 * This source code is licensed under the MIT license found in the 
 * LICENSE file in the root directory of this source tree. 
 */

using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using SecureSign.Core;
using SecureSign.Core.Extensions;

using Microsoft.Extensions.Configuration;
using Serilog.AspNetCore;
using Serilog;

namespace SecureSign.Web
{
	public class Program
	{
		public static int Main(string[] args)
		{
			// The initial "bootstrap" logger is able to log errors during start-up. It's completely replaced by the
			// logger configured in `UseSerilog()` below, once configuration and dependency-injection have both been
			// set up successfully.
			Log.Logger = new LoggerConfiguration()
				.WriteTo.Console()
				.CreateBootstrapLogger();

			Log.Information("Starting up!");

			try
			{
				CreateWebHostBuilder(args).Build().Run();

				Log.Information("Stopped cleanly");
				return 0;
			}
/*			catch (Exception ex)
			{
				Log.Fatal(ex, "An unhandled exception occured during bootstrapping");
				return 1;
			}
			*/
			finally
			{
				Log.CloseAndFlush();
			}
		}

		public static IWebHostBuilder CreateWebHostBuilder(string[] args) =>
			WebHost.CreateDefaultBuilder(args)
				.ConfigureAppConfiguration(builder => builder.AddSecureSignConfig())
                .ConfigureAppConfiguration((builderContext, config) =>
                    {
                        Log.Logger = new LoggerConfiguration()
							.ReadFrom.Configuration(config.Build())
							.CreateLogger();
                    })
				.ConfigureKestrel(options =>
				{
					options.Limits.MaxRequestBodySize = Constants.MAX_ARTIFACT_SIZE;
					options.Limits.MinRequestBodyDataRate = new MinDataRate(
						bytesPerSecond: 240, 
						gracePeriod: System.TimeSpan.FromSeconds(30)
						);
				})
				.UseSerilog()
				.UseStartup<Startup>();
	}
}

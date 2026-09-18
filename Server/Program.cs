using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Autofac;
using Autofac.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Quartz;
using RouterNftConfig.Server.ARP;
using RouterNftConfig.Server.DHCP;
using RouterNftConfig.Server.MACPrefixes;
using RouterNftConfig.Server.NFT;

namespace RouterNftConfig.Server;

class Program {
    public static async Task Main(string[] args) {
        var builder = Host.CreateDefaultBuilder(args);
        builder.ConfigureAppConfiguration(conf => conf.AddJsonFile("appsettings.json", true));
        builder.UseServiceProviderFactory(new AutofacServiceProviderFactory());
        builder.ConfigureWebHostDefaults(webHostBuilder => { webHostBuilder.UseStartup<Program>(); });

        var app = builder.Build();
        await app.RunAsync();
    }

    public Program(IConfiguration configuration)
    {
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        Configuration = configuration;
    }

    public IConfiguration Configuration { get; set; }

    public void Configure(IApplicationBuilder app, ILoggerFactory loggerFactory) {
        AutofacContainer = app.ApplicationServices.GetAutofacRoot();
        app.UseRouting().UseEndpoints(ep => ep.MapControllers());
        app.UseExceptionHandler(
            xhandlerBuilder => {
                xhandlerBuilder.Run(
                    async context => {
                        var errorFeature = context.Features.Get<IExceptionHandlerPathFeature>();
                        if (errorFeature == null || !(errorFeature.Error is ApiErrorException apiErrorException) || !context.Request.Path.StartsWithSegments("api")) {
                            context.Response.StatusCode = 500;
                            context.Response.ContentType = "text/plain";
                            await context.Response.WriteAsync(errorFeature?.Error?.ToString() ?? "No error info");
                            return;
                        }

                        context.Response.StatusCode = 400;
                        await context.Response.WriteAsJsonAsync(
                            new ApiResponse {
                                Success = false,
                                Error = apiErrorException.Error
                            }
                        );
                    }
                );
            }
        );
    }

    public void ConfigureServices(IServiceCollection services)
    {
        services.AddMvc(options => { options.Filters.Add<ApiExceptionFilter>(); }).AddJsonOptions(options =>
                {
                    options.JsonSerializerOptions.PropertyNameCaseInsensitive = true;
                    options.AllowInputFormatterExceptionMessages = true;
                }
            ).AddControllersAsServices()
            .AddJsonOptions(options =>
            {
                options.JsonSerializerOptions.Converters.Add(
                    new JsonStringEnumConverter());
            });

        services.AddRouting();
        services.AddOptions();
        services.AddQuartz();
    }

    public void ConfigureContainer(ContainerBuilder builder) {
        if (Environment.OSVersion.Platform == PlatformID.Unix)
        {
            builder.RegisterType<ArpCliClient>().AsImplementedInterfaces();
            builder.RegisterType<NftCliClient>().AsImplementedInterfaces();
        }
        else
        {
            builder.RegisterType<ArpFileMockClient>().AsImplementedInterfaces();
            builder.RegisterType<NftFileMockClient>().AsImplementedInterfaces();
        }
        builder.RegisterType<IscDhcpLeaseFileReader>().AsImplementedInterfaces();
        builder.RegisterType<IeeeMacVendorResolver>().AsImplementedInterfaces();
        builder.RegisterType<NftManager>().AsSelf();
    }

    public ILifetimeScope AutofacContainer { get; set; }
}

﻿using System;
using System.Reactive.Linq;
using System.Reflection;
using Microsoft.AspNet.SignalR;
using Microsoft.AspNet.SignalR.Infrastructure;
using Microsoft.Owin;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Serialization;
using Ninject;
using Ninject.Modules;
using NuGet.Lucene.Web;
using NuGet.Lucene.Web.Hubs;
using Owin;


[assembly: OwinStartup(typeof(SignalRStartup))]

namespace NuGet.Lucene.Web
{

    public class SignalRStartup
    {
        public void Configuration(IAppBuilder app)
        {
            var hubConfiguration = new HubConfiguration
            {
                EnableDetailedErrors = NuGetWebApiModule.ShowExceptionDetails,
                EnableJSONP = NuGetWebApiModule.EnableCrossDomainRequests,
            };

            app.MapSignalR("/api/signalr", hubConfiguration);
        }
    }

    public class SignalRModule : NinjectModule
    {
        public override void Load()
        {
            var settings = new JsonSerializerSettings
                {
                    ContractResolver = new SelectiveCamelCaseContractResolver(),
                    Converters = { new StringEnumConverter() }
                };

            var jsonNetSerializer = JsonSerializer.Create(settings);
            
            GlobalHost.DependencyResolver = new NinjectSignalRDependencyResolver(Kernel);
            GlobalHost.DependencyResolver.Register(typeof(JsonSerializer), () => jsonNetSerializer);

            var hub = GlobalHost.ConnectionManager.GetHubContext<StatusHub>();

            var repository = Kernel.Get<ILucenePackageRepository>();

            repository.StatusChanged
                .Sample(TimeSpan.FromMilliseconds(250))
                .Subscribe(status => hub.Clients.All.updateStatus(status));
        }
        
        /// <summary>
        /// Uses default contract resolver for types in the SignalR assembly
        /// and camel case for all other types.
        /// </summary>
        public class SelectiveCamelCaseContractResolver : IContractResolver
        {
            private readonly Assembly signalrAssembly;
            private readonly IContractResolver camelCaseContractResolver;
            private readonly IContractResolver defaultContractSerializer;

            public SelectiveCamelCaseContractResolver()
            {
                defaultContractSerializer = new DefaultContractResolver();
                camelCaseContractResolver = new CamelCasePropertyNamesContractResolver();
                signalrAssembly = typeof(Connection).Assembly;
            }

            public JsonContract ResolveContract(Type type)
            {
                if (type.Assembly.Equals(signalrAssembly))
                    return defaultContractSerializer.ResolveContract(type);

                return camelCaseContractResolver.ResolveContract(type);
            }
        }

        public class NinjectSignalRDependencyResolver : DefaultDependencyResolver
        {
            private readonly IKernel kernel;

            public NinjectSignalRDependencyResolver(IKernel kernel)
            {
                this.kernel = kernel;
            }

            public override object GetService(Type serviceType)
            {
                var svc = kernel.TryGet(serviceType);

                if (svc != null) return svc;

                svc = base.GetService(serviceType);

                if (svc != null)
                {
                    kernel.Inject(svc);
                }

                return svc;
            }
        }
    }
}
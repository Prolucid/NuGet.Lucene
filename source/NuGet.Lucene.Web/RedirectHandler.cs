﻿using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http.Routing;

namespace NuGet.Lucene.Web
{
    /// <summary>
    /// Sends a 307 Redirect to the given route with specified route values.
    /// </summary>
    public class RedirectHandler : HttpMessageHandler
    {
        protected readonly string routeName;

        public RedirectHandler(string routeName)
        {
            this.routeName = routeName;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var response = request.CreateResponse(HttpStatusCode.TemporaryRedirect);
            response.Headers.Location = GetRedirectUri(request);
            return Task.FromResult(response);
        }

        protected virtual Uri GetRedirectUri(HttpRequestMessage request)
        {
            var url = GetRedirectLink(request);

            if (url == null)
            {
                throw new InvalidOperationException(string.Format("No route named {0} matched request.", routeName));
            }

            var uriScheme = request.Headers.Where(h => h.Key.ToLower() == "x-forwarded-proto").SelectMany(h => h.Value).FirstOrDefault();
            if (uriScheme != null)
            {
                if (string.Equals(uriScheme, "https", StringComparison.InvariantCultureIgnoreCase))
                    return new UriBuilder(url) { Scheme = Uri.UriSchemeHttps }.Uri;
            }

            return new Uri(url);
        }

        protected virtual string GetRedirectLink(HttpRequestMessage request)
        {
            return new UrlHelper(request).Link(routeName, request.GetRouteData().Values);
        }
    }
}
using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http.Controllers;
using System.Web.Http.Filters;

namespace NuGet.Lucene.Web.Filters
{
    public class ProxyHttpsProtoFilter : ActionFilterAttribute
    {
        public override void OnActionExecuting(HttpActionContext actionContext)
        {
            if (actionContext == null)
                throw new ArgumentNullException("actionContext");

            if (actionContext.Request.Headers.Contains("X-Forwarded-Proto"))
            {
                var uriScheme = Convert.ToString(actionContext.Request.Headers.GetValues("X-Forwarded-Proto").First());
                if (string.Equals(uriScheme, "https", StringComparison.InvariantCultureIgnoreCase))
                    actionContext.Request.RequestUri = new UriBuilder(actionContext.Request.RequestUri) { Scheme = Uri.UriSchemeHttps }.Uri;
            }
        }
    }
}

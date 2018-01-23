using System;
using AspNet.Security.OpenIdConnect.Primitives;

namespace OpenIddict.Compliance.Helpers
{
    public static class OpenIdConnectRequestExtensions
    {
        public static bool HasAcrValue(this OpenIdConnectRequest request, string name)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException("The name cannot be null or empty.", nameof(name));
            }

            if (string.IsNullOrEmpty(request.AcrValues))
            {
                return false;
            }

            var values = request.AcrValues.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (values.Length == 0)
            {
                return false;
            }

            foreach (var value in values)
            {
                if (string.Equals(value, name, StringComparison.Ordinal))
                {
                    return true;
                }
            }

            return false;
        }
    }
}

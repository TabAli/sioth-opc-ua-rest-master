using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace WebPlatform.Exceptions
{
    public class SessionNotAvailableException: Exception
    {
        public SessionNotAvailableException() : base() { }

        public SessionNotAvailableException(String message) : base(message) { }

        public SessionNotAvailableException(String message, Exception innerException) : base(message, innerException) { }
    }
}

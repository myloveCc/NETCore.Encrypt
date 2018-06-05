using System;
using System.Collections.Generic;
using System.Text;

namespace NETCore.Encrypt
{
    /// <summary>
    /// The encrypt string out of max length exception
    /// </summary>
    public class OutofMaxlengthException:Exception
    {
        /// <summary>
        /// The max length of ecnrypt data
        /// </summary>
        public int MaxLength { get; private set; }

        /// <summary>
        /// Error message
        /// </summary>

        public string ErrorMessage { get; set; }
        /// <summary>
        /// Ctor
        /// </summary>
        /// <param name="maxLength"></param>
        public OutofMaxlengthException(int maxLength)
        {
            MaxLength = maxLength;
        }

        /// <summary>
        /// Ctor
        /// </summary>
        /// <param name="maxLength"></param>
        public OutofMaxlengthException(int maxLength, string message) : this(maxLength)
        {
            ErrorMessage = message;
        }
    }
}

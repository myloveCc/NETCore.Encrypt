using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace NETCore.Encrypt.Extensions.Internal
{
    internal static class StreamExtensions
    {
        /// <summary>
        /// Stream write all bytes 
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="byts"></param>
        static public void WriteAll(this Stream stream, byte[] byts)
        {
            stream.Write(byts, 0, byts.Length);
        }
    }
}

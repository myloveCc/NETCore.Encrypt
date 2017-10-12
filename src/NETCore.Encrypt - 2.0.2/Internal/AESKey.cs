using System;
using System.Collections.Generic;
using System.Text;

namespace NETCore.Encrypt.Internal
{
    public class AESKey
    {
        /// <summary>
        /// ase key
        /// </summary>
        public string Key { get; set; }

        /// <summary>
        /// ase IV
        /// </summary>
        public string IV { get; set; }
    }
}

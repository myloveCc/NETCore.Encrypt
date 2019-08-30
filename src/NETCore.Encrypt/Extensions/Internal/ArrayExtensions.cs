using System;
using System.Collections.Generic;
using System.Text;

namespace NETCore.Encrypt.Extensions.Internal
{
    internal static class ArrayExtensions
    {
        /// <summary>
        /// sub datas from array 
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="arr"></param>
        /// <param name="start"></param>
        /// <param name="count"></param>
        /// <returns></returns>
        internal static  T[] Sub<T>(this T[] arr, int start, int count)
        {
            T[] val = new T[count];
            for (var i = 0; i < count; i++)
            {
                val[i] = arr[start + i];
            }
            return val;
        }
    }
}

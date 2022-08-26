namespace Hyperscan.Dotnet
{
    using System;
    using System.Runtime.InteropServices;

    internal static partial class NativeMethods
    {
        [DllImport("Hyperscan.Dotnet.Native.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "create_hyperscan_engine")]
        internal static extern IntPtr CreateHyperscanEngine();

        [DllImport("Hyperscan.Dotnet.Native.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "compile_block_db")]
        internal static extern int CompileBlockDatabase(IntPtr _hyperscanEngine, string patternFile);

        [DllImport("Hyperscan.Dotnet.Native.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "scan_single")]
        internal static extern int ScanSingle(IntPtr _hyperscanEngine, string data);

        [DllImport("Hyperscan.Dotnet.Native.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "clean")]
        internal static extern int Clean(IntPtr _hyperscanEngine);
    }

    public sealed class Hyperscan : IDisposable
    {
        private bool disposedValue;

        private readonly IntPtr _hyperscanEngine;

        /// <summary>
        /// Initilizes the Hyperscan Engine.
        /// </summary>
        public Hyperscan()
        {
            _hyperscanEngine = NativeMethods.CreateHyperscanEngine();
        }

        /// <summary>
        /// Compiles multiple regular expressions into a pattern database (block mode)
        /// </summary>
        /// <param name="patternFile">Path to the pattern file</param>
        public void CompileBlockDatabase(string patternFile)
        {
            NativeMethods.CompileBlockDatabase(_hyperscanEngine, patternFile);
        }

        /// <summary>
        /// The regular expression scanner. Indentifies a match using the compiled patterns.
        /// </summary>
        /// <param name="data"> Single data input to be scanned </param>
        /// <returns> The id of the matched pattern, otherwise -1 </returns>
        public int ScanSingle(string data)
        {
            return NativeMethods.ScanSingle(_hyperscanEngine, data);
        }

        private void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    // TODO: dispose managed state (managed objects)
                }

                // Free unmanaged resources (unmanaged objects) and override finalizer
                NativeMethods.Clean(_hyperscanEngine);
                disposedValue = true;
            }
        }

        // Override finalizer only if 'Dispose(bool disposing)' has code to free unmanaged resources
        ~Hyperscan()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: false);
        }

        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}

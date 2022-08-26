namespace Hyperscan.Dotnet
{
    using System;
    using System.Runtime.InteropServices;

    internal static partial class NativeMethods
    {
        [DllImport("Hyperscan.Dotnet.Native.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "compile_block_db")]
        internal static extern int CompileBlockDatabase(string path);

        [DllImport("Hyperscan.Dotnet.Native.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "scan_single")]
        internal static extern int ScanSingle(string dataInput);

        [DllImport("Hyperscan.Dotnet.Native.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "clean")]
        internal static extern int Clean();
    }

    public sealed class Hyperscan : IDisposable
    {
        private bool disposedValue;

        public Hyperscan()
        {
        }

        public void CompileBlockDatabase(string patternFile)
        {
            NativeMethods.CompileBlockDatabase(patternFile);
        }

        public int ScanSingle(string dataInput)
        {
            return NativeMethods.ScanSingle(dataInput);
        }

        public void Clean()
        {
            NativeMethods.Clean();
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
                NativeMethods.Clean();
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
